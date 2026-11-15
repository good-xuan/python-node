#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import struct
import base64
import asyncio
from aiohttp import web

# 优先启用 uvloop 提升异步 I/O 性能
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

# 基础配置
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')
DOMAIN = os.environ.get('DOMAIN', 'cf.877774.xyz')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
SUB_PATH = os.environ.get('SUB_PATH', UUID[-12:]).lstrip('/')
WSPATH = os.environ.get('WSPATH', UUID[:8]).lstrip('/')

UUID_BYTES = bytes.fromhex(UUID.replace('-', ''))
VLESS_OK_HEADER = b'\x00\x00'
BUFFER_SIZE = 65536


def set_tcp_nodelay(transport) -> None:
    """禁用 Nagle 算法，降低小包传输延迟"""
    if transport is None:
        return
    sock = transport.get_extra_info('socket')
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass


async def ws_to_tcp(ws: web.WebSocketResponse, writer: asyncio.StreamWriter) -> None:
    transport = writer.transport
    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.BINARY:
                writer.write(msg.data)
                if transport.get_write_buffer_size() > BUFFER_SIZE:
                    await writer.drain()
            elif msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.CLOSING, web.WSMsgType.ERROR):
                break
    except Exception:
        pass


async def tcp_to_ws(reader: asyncio.StreamReader, ws: web.WebSocketResponse) -> None:
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            await ws.send_bytes(data)
    except Exception:
        pass


async def vless_handler(request: web.Request) -> web.StreamResponse:
    ws = web.WebSocketResponse(heartbeat=30.0, compress=False, max_msg_size=0)
    # 非 WebSocket 握手请求直接返回 403
    if not ws.can_prepare(request).ok:
        return web.Response(status=403, text='403 Forbidden', content_type='text/plain')

    await ws.prepare(request)
    set_tcp_nodelay(request.transport)

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
        if idx + 4 > len(data) or data[idx] != 1:  # 仅处理 TCP (cmd = 1)
            await ws.close()
            return ws

        port = struct.unpack('!H', data[idx + 1:idx + 3])[0]
        atyp = data[idx + 3]
        idx += 4

        if atyp == 1:  # IPv4
            if idx + 4 > len(data):
                await ws.close()
                return ws
            host = socket.inet_ntoa(data[idx:idx + 4])
            idx += 4
        elif atyp == 2:  # 域名
            if idx + 1 > len(data):
                await ws.close()
                return ws
            host_len = data[idx]
            idx += 1
            if idx + host_len > len(data):
                await ws.close()
                return ws
            host = data[idx:idx + host_len].decode('utf-8', errors='ignore')
            idx += host_len
        else:  # 仅走 IPv4，直接拒绝 IPv6 (atyp == 3) 及未知地址类型
            await ws.close()
            return ws

        # 响应协议握手成功 [version: 0, addon_len: 0]
        await ws.send_bytes(VLESS_OK_HEADER)

        # 强制仅使用 IPv4 直连目标服务器（兼容 uvloop，跳过 IPv6 解析与连接等待）
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=socket.AF_INET),
            timeout=10.0
        )
        set_tcp_nodelay(writer.transport)

        # 补发首包附带的 payload 数据
        if idx < len(data):
            writer.write(data[idx:])
            await writer.drain()

        # 双向并发流传输
        t1 = asyncio.create_task(ws_to_tcp(ws, writer))
        t2 = asyncio.create_task(tcp_to_ws(reader, ws))

        _, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    except Exception:
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        if not ws.closed:
            await ws.close()

    return ws


async def sub_handler(request: web.Request) -> web.Response:
    tls = 'tls' if DOMAIN != '127.0.0.1' else 'none'
    port = 443 if tls == 'tls' else PORT
    vless_uri = (
        f"vless://{UUID}@{DOMAIN}:{port}"
        f"?encryption=none&security={tls}&sni={DOMAIN}&fp=chrome&type=ws&host={DOMAIN}&path=%2F{WSPATH}#Node"
    )
    b64_sub = base64.b64encode(vless_uri.encode()).decode()
    return web.Response(text=b64_sub + '\n', content_type='text/plain')


async def forbidden_handler(request: web.Request) -> web.Response:
    return web.Response(status=403, text='403 Forbidden', content_type='text/plain')


def main() -> None:
    app = web.Application()
    app.router.add_get(f'/{SUB_PATH}', sub_handler)
    app.router.add_get(f'/{WSPATH}', vless_handler)
    app.router.add_route('*', '/', forbidden_handler)
    app.router.add_route('*', '/{tail:.*}', forbidden_handler)
    web.run_app(app, host='0.0.0.0', port=PORT, access_log=None)


if __name__ == '__main__':
    main()
