import logging
import re
import select

PACKET_SIZE = 4096

class ChecksumError(Exception):
    pass

class GDBPacket():

    def __init__(self, packet):
        self.packet = packet

class GDBClient():

    def __init__(self, conn, addr):
        self.sock = conn
        self.addr = addr
        self.sock.setblocking(True)
        self.fsock = self.sock.makefile(mode='rw')
        self.buffer = b''


    def read_packet(self):
        epoll = select.epoll()
        epoll.register(self.sock.fileno(),  select.EPOLLIN | select.EPOLLHUP
                       | select.EPOLLRDHUP)
        while True:
            if len(self.buffer) == 0:
                events = epoll.poll()
                for fileno, event in events:
                    if fileno == self.sock.fileno():
                        if event == select.EPOLLIN:
                            self.buffer = self.sock.recv(PACKET_SIZE)
                            logging.debug('new buffer: %s', self.buffer)
                        if event == select.EPOLLHUP:
                            logging.debug('EPOLLHUP')
                        if event == select.EPOLLRDHUP:
                            logging.debug('EPOLLRDHUP')
                    else:
                        raise RuntimeError('unknown fd %d', fileno)
            # ack ok ?
            m = re.match(b'\+', self.buffer)
            if m:
                logging.debug('acknowledged')
                self.buffer = self.buffer[1:]
                continue
            m = re.match(b'-', self.buffer)
            # ack retransmit
            if m:
                logging.debug('retransmit last packet')
                self.buffer = self.buffer[1:]
                raise RuntimeError('not implemented')
                # continue
            # CTRL-C ?
            m = re.match(b'\x03', self.buffer)
            if m:
                self.buffer = self.buffer[1:]
                raise RuntimeError('not implemented')
            # packet ?
            m = re.match(b'\$(?P<data>.*)#(?P<checksum>..)', self.buffer)
            if m:
                packet_data = m.group('data')
                packet_checksum = int(m.group('checksum'), 16)
                self.validate_packet(packet_data, packet_checksum)
                self.buffer = self.buffer[m.endpos+1:]
                return packet_data
            logging.debug('buffer data: %s', self.buffer)
            # not enough packet data to match a packet regex
            raise RuntimeError('not implemented')

    def validate_packet(self, packet_data, packet_checksum):
        checksum = sum(packet_data) % 256
        if checksum != packet_checksum:
            raise ChecksumError('invalid checksum received')

    def send_ack(self, validity):
        if validity:
            c = b'+'
        else:
            c = b'-'
        self.sock.sendall(c)

    def handle_connexion(self):
        logging.info('connected')

        while True:
            packet_data = None
            try:
                packet_data = self.read_packet()
            except ChecksumError:
                # ask to resend packet
                logging.debug('invalid checksum')
                self.send_ack(False)
            else:
                logging.info('new packet: %s', packet_data)
                self.send_ack(True)

            cmd, cmd_data = chr(packet_data[0]), packet_data[1:]
            # dispatcher
            try:
                handler_name = 'handle_{}'.format(cmd)
                handler = getattr(self, handler_name)
                logging.info('calling {}'.format(handler_name))
                handler(cmd_data)
            except AttributeError:
                logging.info('unhandled command {}'.format(cmd))

    def handle_q(self, cmd_data):
        pass