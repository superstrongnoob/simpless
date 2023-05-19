import asyncio
import socket
from loguru import logger
from config import global_config
from utils import gen_iv, gen_key, get_iv_len, get_key_len
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from s5 import ss_parse_addr


__all__ = ['create_shadowsocks_srvs']





########################################################################
############################TCP SERVER##################################
########################################################################


class TcpNode:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, password: str, idle_timeout: int):
        self._reader_local = reader
        self._writer_local = writer
        self._reader_remote = None
        self._writer_remote = None
        self._method = method
        self._password = password
        self._idle_timeout = idle_timeout
        self._first_decrypt = True
        self._first_encrypt = True
        self._iv_len = get_iv_len(method)
        self._key_len = get_key_len(method)
        self._key = gen_key(password, self._key_len)
        self._iv_encrypt = None
        self._iv_decrypt = None
        self._encrypt_ctx = None
        self._decrypt_ctx = None
        self._task_local = None
        self._task_remote = None
        self._last_interaction = asyncio.get_event_loop().time()

        if self._idle_timeout:
            asyncio.create_task(self._timeout_check())

    async def _timeout_check(self):
        while True:
            current_time = asyncio.get_event_loop().time()
            if current_time - self._last_interaction > self._idle_timeout:
                if self._task_local:
                    self._task_local.cancel()
                if self._task_remote:
                    self._task_remote.cancel()

                break
            await asyncio.sleep(1)  # 检查间隔

    async def forever(self) -> None:
        # 握手
        bok = await self._stage_handshake()
        if bok:
            # 双向数据交换
            self._task_local = asyncio.create_task(self._stage_local_cycle())
            self._task_remote = asyncio.create_task(self._stage_remote_cycle())

            # 使用asyncio.wait()等待任意一个任务完成
            done, pending = await asyncio.wait(
                [self._task_local, self._task_remote],
                return_when=asyncio.FIRST_COMPLETED
            )

            # 取消尚未完成的任务
            for task in pending:
                task.cancel()


        # 关闭连接
        try:
            self._writer_local.close()
            await self._writer_local.wait_closed()
        except Exception:
            pass

        try:
            if self._writer_remote:
                self._writer_remote.close()
                await self._writer_remote.wait_closed()
        except Exception:
            pass



    # 处理握手阶段
    async def _stage_handshake(self) -> bool:

        try:
            data = await asyncio.wait_for(self._reader_local.read(64*1024), 10)
        except asyncio.TimeoutError:
            # 指定时间内没有进行握手
            return False
        except (BrokenPipeError, ConnectionResetError, asyncio.CancelledError):
            # 链接已经断开
            return False
        except Exception as e:
            logger.error(f"[ss] unknow exception when handshake [${e}]")
            return False

        # 解密数据
        data = self._stream_decrypt(data)
        if not data:
            return False

        # 得到目标地址信息
        try:
            hdr_len, (addr, port) = ss_parse_addr(data)
        except Exception as e:
            logger.error(f'[ss] s5 parse failed[{e}]')
            return False

        if hdr_len == 0 or addr == '' or port == 0:
            logger.error(f'[ss] s5 parse failed[hdr:{hdr_len}] addr[{addr}] port[{port}]')
            return False

        domain = addr

        try:
            local_addr = self._writer_local.get_extra_info('peername')
            logger.info(f"[ss] tcp {local_addr[0]}:{local_addr[1]} -> {domain}:{port}")
        except (AttributeError, RuntimeError):
            return False

        # 连接远程地址
        try:
            self._reader_remote, self._writer_remote = await asyncio.open_connection(host=addr, port=port)
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError, asyncio.CancelledError) as e:
            logger.error(f"[ss] connection to [{domain}:{port}] exception [{e}]")
            return False
        except Exception as e:
            logger.error(f"[ss] connection to [{domain}:{port}] unknow exception [{e}]")
            return False

        # 有可能第一个包中就包含额外需要发送的数据
        if len(data) > hdr_len:
            data = data[hdr_len:]
            try:
                self._writer_remote.write(data)
                await self._writer_remote.drain()
            except (ConnectionError, asyncio.CancelledError, BrokenPipeError, ConnectionResetError) as e:
                logger.error(f"[ss] response handshake to [{domain}:{port}] exception [{e}]")
                return False
            except Exception as e:
                logger.error(f"[ss] response handshake to [{domain}:{port}] unknow exception [{e}]")
                return False
        return True


    # LOCAL
    async def _stage_local_cycle(self) -> None:
        while True:
            try:
                data = await self._reader_local.read(64*1024)
            except (BrokenPipeError, ConnectionResetError, ConnectionError, asyncio.CancelledError):
                break
            except Exception as e:
                break


            if not data: break

            # 从ss local来的数据是加密的 需要解密
            data = self._stream_decrypt(data)
            if not data: break

            # 发往目标服务器
            try:
                self._writer_remote.write(data)
                await self._writer_remote.drain()
            except (BrokenPipeError, ConnectionResetError, ConnectionError, asyncio.CancelledError):
                break
            except Exception as e:
                break


    # REMOTE
    async def _stage_remote_cycle(self) -> None:
        while True:
            try:
                data = await self._reader_remote.read(64*1024)
            except (BrokenPipeError, ConnectionResetError, ConnectionError, asyncio.CancelledError):
                break
            except Exception as e:
                break

            if not data: break

            # 发往ss local的数据需要加密
            data = self._stream_encrypt(data)
            if not data: break

            # 发往 ss local
            try:
                self._writer_local.write(data)
                await self._writer_local.drain()
            except (BrokenPipeError, ConnectionResetError, ConnectionError, asyncio.CancelledError):
                break
            except Exception as e:
                break


    # 加密
    def _stream_encrypt(self, data: bytes) -> bytes:
        result = b''

        if self._first_encrypt:
            seed = "seed name here"
            self._iv_encrypt = gen_iv(seed, self._iv_len)
            cipher = Cipher(algorithms.AES(self._key), modes.CFB(self._iv_encrypt))
            self._encrypt_ctx = cipher.encryptor()
            result += self._iv_encrypt

            self._first_encrypt = False

        result += self._encrypt_ctx.update(data)
        return result


    # 解密
    def _stream_decrypt(self, data: bytes) -> bytes:
        result = b''

        if self._first_decrypt:
            if len(data) < self._iv_len:
                return result

            self._iv_decrypt = data[:self._iv_len]
            cipher = Cipher(algorithms.AES(self._key), modes.CFB(self._iv_decrypt))
            self._decrypt_ctx = cipher.decryptor()
            data = data[self._iv_len:]

            self._first_decrypt = False

        result += self._decrypt_ctx.update(data)
        return result






class ShadowsocksServerTcp:
    def __init__(self, listen_addr: str, listen_port: int, method: str, password: str, idle_timeout: int):
        self._listen_addr = listen_addr
        self._listen_port = listen_port
        self._method = method
        self._password = password
        self._idle_timeout = idle_timeout
        self._server = None
        self._stop_event = asyncio.Event()
        self._link_nums = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_connection,
            host=self._listen_addr,
            port=self._listen_port,
            reuse_address=True,
            reuse_port=True
        )

        # 等待停止事件
        await self._stop_event.wait()

        # 关闭服务器并等待所有连接关闭
        self._server.close()

    async def stop(self) -> None:
        self._stop_event.set()

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # 每个TCP连接都创建一个NODE实例
        self._link_nums += 1
        node = TcpNode(reader, writer, self._method, self._password, self._idle_timeout)
        await node.forever()
        self._link_nums -= 1

















########################################################################
############################UDP SERVER##################################
########################################################################

class DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, msg_handler, close_handler=None, idle_timeout: int=None, local_addr: tuple=None, remote_addr: tuple=None):
        self._msg_handler = msg_handler
        self._close_handler = close_handler
        self._transport = None
        self._local_addr = local_addr
        self._remote_addr = remote_addr
        self._idle_timeout = idle_timeout
        self._last_interaction = asyncio.get_event_loop().time()

        if self._idle_timeout:
            asyncio.create_task(self._timeout_check())

    async def _timeout_check(self):
        while True:
            current_time = asyncio.get_event_loop().time()
            if current_time - self._last_interaction > self._idle_timeout:
                self._close_callback(None)
                self._close_transport()

                break
            await asyncio.sleep(1)  # 检查间隔

    def update_interaction(self):
        self._last_interaction = asyncio.get_event_loop().time()

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self.update_interaction()
        self._msg_handler(data, addr, self)

    def error_received(self, exc):
        self._close_callback(exc)
        self._close_transport()

    def connection_lost(self, exc):
        self._close_callback(exc)
        self._close_transport()

    def local_address(self) -> tuple:
        return self._local_addr

    def remote_address(self) -> tuple:
        return self._remote_addr

    def transport(self):
        return self._transport

    def _close_callback(self, exc):
        if self._close_handler:
            self._close_handler(exc, self)
            self._close_handler = None

    def _close_transport(self):
        if self._transport:
            self._transport.close()
            self._transport = None


class ShadowsocksServerUdp:
    def __init__(self, listen_addr: str, listen_port: int, method: str, password: str, idle_timeout: int):
        self._listen_addr = listen_addr
        self._listen_port = listen_port
        self._method = method
        self._password = password
        self._idle_timeout = idle_timeout
        self._transport = None
        self._stop_event = asyncio.Event()
        self._iv_len = get_iv_len(method)
        self._key_len = get_key_len(method)
        self._key = gen_key(password, self._key_len)
        self._link_map = dict()
        self._link_nums = 0


    async def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocol(self._on_datagram_local_received),
            local_addr=(self._listen_addr, self._listen_port),
            reuse_port=True
        )

        # 等待停止事件
        await self._stop_event.wait()

        self._transport.close()


    async def stop(self) -> None:
        self._stop_event.set()

    def _on_datagram_local_received(self, data, addr_c, prot) -> None:
        asyncio.create_task(self._on_datagram_local_received_do(data, addr_c, prot))

    # 接收到了 ss local 的消息
    # 只通过一个UDP句柄进行监听 所以通讯是一对多的关系
    async def _on_datagram_local_received_do(self, data, addr_c, prot) -> None:
        data = self._dgram_decrypt(data)
        if not data:
            return

        # 得到目标地址信息
        try:
            hdr_len, (addr_s, port) = ss_parse_addr(data) # 注意这里可能是IPV4 IPV6 DOMAIN
        except Exception as e:
            logger.error(f'[ss] s5 parse failed[{e}]')
            return

        if hdr_len == 0 or addr_s == '' or port == 0:
            logger.error(f'[ss] s5 parse failed[hdr:{hdr_len}] addr[{addr_s}] port[{port}]')
            return

        # gen map key
        link_key = f"{addr_c[0]}:{addr_c[1]}-{addr_s}:{port}"
        if link_key not in self._link_map:

            loop = asyncio.get_event_loop()
            transport, prot = await loop.create_datagram_endpoint(
                lambda: DatagramProtocol(self._on_datagram_remote_received, self._on_datagram_remote_connection_lost, self._idle_timeout, addr_c, (addr_s, port)),
                remote_addr=(addr_s, port)
            )

            self._link_map[link_key] = prot
            self._link_nums += 1

            logger.info(f"[ss] udp {addr_c[0]}:{addr_c[1]} -> {addr_s}:{port}")
        else:
            transport = self._link_map[link_key].transport()

        # 将数据发往目标服务器
        data = data[hdr_len:]

        try:
            transport.sendto(data, (addr_s, port))
        except (OSError, TypeError, ValueError) as e:
            logger.error(f"[ss] udp sendto exception [{e}]")


    # 接收到了 目标的消息
    def _on_datagram_remote_received(self, data: bytes, addr: tuple, prot: DatagramProtocol) -> None:
        hdr = b''
        addr_s = prot.remote_address()

        got = False
        try:
            bs = socket.inet_pton(socket.AF_INET, addr_s[0])
            hdr += b'\1' + bs + addr_s[1].to_bytes(2, 'big')

            got = True
        except socket.error:
            pass

        if not got:
            try:
                bs = socket.inet_pton(socket.AF_INET6, addr_s[0])
                hdr += b'\4' + bs + addr_s[1].to_bytes(2, 'big')

                got = True
            except socket.error:
                pass

        if not got:
            bs = addr_s[0].encode()
            hdr += b'\3' + bs + addr_s[1].to_bytes(2, 'big')

        data = self._dgram_encrypt(hdr + data)
        addr_c = prot.local_address()

        try:
            self._transport.sendto(data, addr_c)
        except (OSError, TypeError, ValueError):
            logger.error(f"[ss] udp sendto exception")


    # 目标断开
    def _on_datagram_remote_connection_lost(self, exc, prot: DatagramProtocol) -> None:

        key_to_del = ''
        for key, value in self._link_map.items():
            if prot == value:
                key_to_del = key
                break

        if key_to_del:
            del self._link_map[key_to_del]
            self._link_nums -= 1



    # TODO 针对每个链接进行加密 而不是每个数据包

    # 加密
    def _dgram_encrypt(self, data: bytes) -> bytes:
        result = b''

        seed = 'seed name here'
        iv_encrypt = gen_iv(seed, self._iv_len)
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv_encrypt))
        encrypt_ctx = cipher.encryptor()

        result = iv_encrypt + encrypt_ctx.update(data)

        return result


    # 解密
    def _dgram_decrypt(self, data: bytes) -> bytes:
        result = b''

        if len(data) < self._iv_len:
            return result

        iv_decrypt = data[:self._iv_len]
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv_decrypt))
        decrypt_ctx = cipher.decryptor()

        data = data[self._iv_len:]
        result = decrypt_ctx.update(data)

        return result
























# 创建服务包装函数
async def create_shadowsocks_srvs(listen_addr, listen_port, method, password, idle_timeout) -> None:
    tcp_server = ShadowsocksServerTcp(listen_addr, listen_port, method, password, idle_timeout)
    udp_server = ShadowsocksServerUdp(listen_addr, listen_port, method, password, idle_timeout)

    tasks = {
        'tcp_server': asyncio.create_task(tcp_server.start()),
        'udp_server': asyncio.create_task(udp_server.start())
    }



    done, pending = await asyncio.wait(
        tasks.values(),
        return_when=asyncio.FIRST_COMPLETED
    )

    await tcp_server.stop()
    await udp_server.stop()

    # 有其中一个协程循环退出时 另一个也主动cancel
    for task in pending:
        task.cancel()

    for name, task in tasks.items():
        if task in done:
            logger.info(f"[ss] completed task: {name}, result: {task.result()}")
        else:
            logger.info(f"[ss] cancelled task: {name}")

