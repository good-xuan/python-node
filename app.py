#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import struct
import base64
import asyncio
from aiohttp import web

# 基础配置
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')
DOMAIN = os.environ.get('DOMAIN', 'cf.877774.xyz')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
SUB_PATH = os.environ.get('SUB_PATH', UUID[-12:])
WSPATH = os.environ.get('WSPATH', UUID[:8])
UUID_BYTES = bytes.fromhex(UUID.replace('-', ''))

async def forward(src_read, dst_write, is_ws_to_tcp=True):
    try:
        if is_ws_to_tcp:
            async for msg in src_read:
                if msg.type == web.WSMsgType.BINARY:
                    dst_write.write(msg.data)
                    await dst_write.drain()
                elif msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.CLOSING, web.WSMsgType.ERROR):
                    break
        else:
            while True:
                data = await src_read.read(16384)
                if not data:
                    break
                await dst_write.send_bytes(data)
    except (asyncio.CancelledError, ConnectionResetError, Exception):
        pass

async def vless_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
        if first_msg.type != web.WSMsgType.BINARY:
            await ws.close()
            return ws

        data = first_msg.data
        if len(data) < 18 or data[0] != 0 or data[1:17] != UUID_BYTES:
            await ws.close()
            return ws

        # 解析 VLESS 头结构
        idx = 18 + data[17]
        if idx + 3 > len(data) or data[idx] != 1:  # 仅处理 TCP (cmd = 1)
            await ws.close()
            return ws

        idx += 1
        port = struct.unpack('!H', data[idx:idx+2])[0]
        idx += 2
        atyp = data[idx]
        idx += 1

        if atyp == 1:       # IPv4
            host = socket.inet_ntoa(data[idx:idx+4])
            idx += 4
        elif atyp == 2:     # 域名
            host_len = data[idx]
            idx += 1
            host = data[idx:idx+host_len].decode('utf-8', errors='ignore')
            idx += host_len
        elif atyp == 3:     # IPv6
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
            idx += 16
        else:
            await ws.close()
            return ws

        # 响应协议握手成功 [version: 0, addon_len: 0]
        await ws.send_bytes(bytes([0, 0]))

        # 直连目标服务器
        reader, writer = await asyncio.open_connection(host, port)

        # 补发首包未传完的 payload 数据
        if idx < len(data):
            writer.write(data[idx:])
            await writer.drain()

        # 双向并发流传输
        ws_to_tcp = asyncio.create_task(forward(ws, writer, True))
        tcp_to_ws = asyncio.create_task(forward(reader, ws, False))

        done, pending = await asyncio.wait([ws_to_tcp, tcp_to_ws], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    except Exception:
        pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        if not ws.closed:
            await ws.close()

    return ws

async def sub_handler(request: web.Request) -> web.Response:
    # 外部传入环境变量 DOMAIN 则默认走 TLS/443 反代，否则降级直连
    tls = 'tls' if DOMAIN != '127.0.0.1' else 'none'
    port = 443 if tls == 'tls' else PORT
    vless_uri = f"vless://{UUID}@{DOMAIN}:{port}?encryption=none&security={tls}&sni={DOMAIN}&fp=chrome&type=ws&host={DOMAIN}&path=%2F{WSPATH}#Node"
    b64_sub = base64.b64encode(vless_uri.encode()).decode()
    return web.Response(text=b64_sub + '\n', content_type='text/plain')

async def index_handler(request: web.Request) -> web.Response:
    if os.path.exists('index.html'):
        with open('index.html', 'r', encoding='utf-8') as f:
            return web.Response(text=f.read(), content_type='text/html')
    return web.Response(text='OK', content_type='text/plain')

def main():
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_get(f'/{SUB_PATH}', sub_handler)
    app.router.add_get(f'/{WSPATH}', vless_handler)
    web.run_app(app, host='0.0.0.0', port=PORT, access_log=None)

if __name__ == '__main__':
    main()
