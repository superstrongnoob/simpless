import os
import sys
import asyncio
import socket
from loguru import logger
from config import global_config
from shadowsocks_srv import create_shadowsocks_srvs



def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('www.baidu.com', 80))
        return s.getsockname()[0]


async def main():
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    log_name = 'logs/server.log'
    log_path = os.path.join(cur_dir, log_name)

    # 每周创建一个新的日志文件 最多保留四个
    # logger.add(log_path, rotation='1 week', retention=4, encoding="utf-8")

    listen_addr = global_config.get('listenAddress')
    listen_port = global_config.get('listenPort')
    method = global_config.get('method')
    password = global_config.get('password')
    idle_timeout = global_config.get('idleTimeout')

    # 如果指定了 0.0.0.0 动态获取一下可用本地IP
    if '0.0.0.0' == listen_addr:
        listen_addr = get_local_ip()

    s = f'[ss] start server at[{listen_addr}:{listen_port}]'
    logger.info(s)

    s = f'[ss] method[{method}] password[{password}]'
    logger.info(s)

    # 启动SS服务
    await create_shadowsocks_srvs(listen_addr, listen_port, method, password, idle_timeout)







class MyPolicy(asyncio.DefaultEventLoopPolicy):
    def new_event_loop(self):
        selector = selectors.SelectSelector()
        return asyncio.SelectorEventLoop(selector)


if __name__ == '__main__':
    with_uvloop = False
    try:
        import uvloop
        with_uvloop = True
    except ImportError:
        pass

    if with_uvloop:
        if sys.version_info >= (3, 11):
            with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
                runner.run(main())
        else:
            uvloop.install()
            asyncio.run(main())
    else:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(MyPolicy())
        asyncio.run(main())

