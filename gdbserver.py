import logging
import socket
# from concurrent.futures import ThreadPoolExecutor

from gdbclient import GDBClient

MAX_CLIENTS = 1

class GDBServer():

    def __init__(self, address, port, client_cls=GDBClient):
        self.address = address
        self.port = port
        self.client_cls = client_cls
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
        log = logging.getLogger('server')
        log.info('listening on %s:%d', self.address, self.port)

        while True:
            conn, addr = self.sock.accept()
            log.info('new client %s', addr)
            client = self.client_cls(conn, addr)
            client.handle_rsp()
            # future = self.pool.submit(client.handle_connexion)
            # self.future_to_client[future] = client