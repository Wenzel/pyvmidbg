import logging
import socket
# from concurrent.futures import ThreadPoolExecutor

from .gdbstub import GDBStub

MAX_CLIENTS = 1


class GDBServer:

    def __init__(self, address, port, stub_cls=GDBStub, stub_args=()):
        self.log = logging.getLogger('server')
        self.address = address
        self.port = port
        self.stub_cls = stub_cls
        self.stub_args = stub_args
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.future_to_client = {}
        # self.pool = ThreadPoolExecutor(max_workers=MAX_CLIENTS)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        # self.pool.shutdown()
        self.sock.close()

    def listen(self):
        self.sock.listen(MAX_CLIENTS)
        self.log.info('listening on %s:%d', self.address, self.port)

        do_listen = True
        while do_listen:
            self.log.debug('ready for next client')
            try:
                conn, addr = self.sock.accept()
                self.log.info('new client %s', addr)
                with self.stub_cls(conn, addr, *self.stub_args) as client:
                    client.handle_rsp()
            except KeyboardInterrupt:
                do_listen = False
            # future = self.pool.submit(client.handle_connexion)
            # self.future_to_client[future] = client
        self.log.info('closing server')