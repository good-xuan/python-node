#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import struct
import base64
import asyncio
import logging
import ipaddress
import aiohttp
from aiohttp import web

# 环境变量
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
DOMAIN = os.environ.get('DOMAIN', '')                                 # 分配的域名或反代域名,不带https://
SUB_PATH = os.environ.get('SUB_PATH', UUID[-12:])                     # 节点订阅token,默认后12位
NAME = os.environ.get('NAME', '')                                     # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])                           # 节点路径,默认前8位
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # HTTP/WS 端口
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

# 审计与测速屏蔽域名
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# DNS 内存缓存: {host: (ip, expire_time)}
DNS_CACHE = {}
DNS_CACHE_TTL = 300  # 缓存 5 分钟

# 日志配置
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
               for blocked in BLOCKED_DOMAINS)

async def resolve_host(host: str) -> str:
    # 纯 IP 直接返回
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    
    # 命中内存缓存
    now = time.time()
    if host in DNS_CACHE:
        cached_ip, expire_at = DNS_CACHE[host]
        if now < expire_at:
            return cached_ip

    # 利用本地系统 resolver 异步解析
    loop = asyncio.get_running_loop()
    try:
        addrinfo = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        if addrinfo:
            target_ip = addrinfo[0][4][0]
            DNS_CACHE[host] = (target_ip, now + DNS_CACHE_TTL)
            return target_ip
    except Exception as e:
        if DEBUG:
            logger.debug(f"Local DNS resolve failed for {host}: {e}")

    return host

async def get_isp(session: aiohttp.ClientSession):
    global ISP
    try:
        async with session.get('https://api.ip.sb/geoip', 
                               headers={'User-Agent': 'Mozilla/5.0'}, 
                               timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json()
                ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                return
    except Exception:
        pass
    
    try:
        async with session.get('http://ip-api.com/json', 
                               headers={'User-Agent': 'Mozilla/5.0'}, 
                               timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json()
                ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                return
    except Exception:
        pass
    
    ISP = 'Unknown'

async def get_ip(session: aiohttp.ClientSession):
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with session.get('https://api-ipv4.ip.sb/ip', 
                                   timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    ip = (await resp.text()).strip()
                    CurrentDomain = ip
                    Tls = 'none'
                    CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

class ProxyHandler:
    def __init__(self, uuid_hex: str):
        self.uuid_bytes = bytes.fromhex(uuid_hex)
        
    async def handle_vless(self, websocket: web.WebSocketResponse, first_msg: bytes) -> bool:
        """处理 VLESS 协议握手及双向流转发"""
        writer = None
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            # 校验 UUID
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            addon_len = first_msg[17]
            i = 18 + addon_len
            if i + 3 > len(first_msg):
                return False
            
            # 检查命令字 (仅支持 TCP: 0x01)
            cmd = first_msg[i]
            i += 1
            if cmd != 1:
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            # 解析目标地址
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = socket.inet_ntoa(first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode('utf-8', errors='ignore')
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = socket.inet_ntop(socket.AF_INET6, first_msg[i:i+16])
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 发送 VLESS 成功响应头
            await websocket.send_bytes(bytes([0, 0]))
            
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
            except Exception as e:
                if DEBUG:
                    logger.debug(f"Target connection failed ({resolved_host}:{port}): {e}")
                return False

            # 下发首包剩余负载
            if i < len(first_msg):
                writer.write(first_msg[i:])
                await writer.drain()
            
            # 双向转发定义
            async def forward_ws_to_tcp():
                try:
                    async for msg in websocket:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            writer.write(msg.data)
                            await writer.drain()
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                            break
                except (asyncio.CancelledError, ConnectionResetError):
                    pass

            async def forward_tcp_to_ws():
                try:
                    while not websocket.closed:
                        # 采用 16KB 缓冲区以提升高并发网络吞吐
                        data = await reader.read(16384)
                        if not data:
                            break
                        await websocket.send_bytes(data)
                except (asyncio.CancelledError, ConnectionResetError):
                    pass

            ws_task = asyncio.create_task(forward_ws_to_tcp())
            tcp_task = asyncio.create_task(forward_tcp_to_ws())

            # 任意一端连接断开时，立即取消并回收另一端任务
            done, pending = await asyncio.wait(
                [ws_task, tcp_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False
            
        finally:
            # 保证远端套接字及 WebSocket 优雅关闭，防止句柄挂起
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            if not websocket.closed:
                try:
                    await websocket.close()
                except Exception:
                    pass

async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)
    
    c_uuid = UUID.replace('-', '')
    proxy = ProxyHandler(c_uuid)
    
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0:
            await proxy.handle_vless(ws, msg_data)
        else:
            await ws.close()
            
    except (asyncio.TimeoutError, Exception) as e:
        if DEBUG:
            logger.error(f"WebSocket session error: {e}")
        await ws.close()
    
    return ws

async def http_index_handler(request: web.Request) -> web.Response:
    if os.path.exists('index.html'):
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except Exception:
            pass
    return web.Response(text='Hello world!', content_type='text/html')

async def http_sub_handler(request: web.Request) -> web.Response:
    session: aiohttp.ClientSession = request.app['http_session']
    await get_isp(session)
    await get_ip(session)
    
    name_part = f"{NAME}-{ISP}" if NAME else ISP
    tls_param = 'tls' if Tls == 'tls' else 'none'
    
    vless_url = (
        f"vless://{UUID}@{CurrentDomain}:{CurrentPort}"
        f"?encryption=none&security={tls_param}&sni={CurrentDomain}"
        f"&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
    )
    base64_content = base64.b64encode(vless_url.encode('utf-8')).decode('utf-8')
    return web.Response(text=base64_content + '\n', content_type='text/plain')

async def on_startup(app: web.Application):
    # 全局单例 ClientSession，连接池共享
    app['http_session'] = aiohttp.ClientSession()

async def on_cleanup(app: web.Application):
    session: aiohttp.ClientSession = app.get('http_session')
    if session and not session.closed:
        await session.close()

def create_app() -> web.Application:
    app = web.Application()
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    
    # 严格路径映射
    app.router.add_get('/', http_index_handler)
    app.router.add_get(f'/{SUB_PATH}', http_sub_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    return app

async def main():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    
    # 遵循 EAFP 规范直接启动监听，遇到冲突自动顺延
    current_port = PORT
    max_attempts = 100
    started = False
    
    for port in range(current_port, current_port + max_attempts):
        try:
            site = web.TCPSite(runner, '0.0.0.0', port)
            await site.start()
            logger.info(f"✅ Server is running on port {port}")
            started = True
            break
        except OSError:
            logger.warning(f"Port {port} is in use, trying next port...")
    
    if not started:
        logger.error("No available ports found")
        await runner.cleanup()
        sys.exit(1)
        
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")