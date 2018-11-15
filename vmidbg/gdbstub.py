import logging
import re
import select
import socket
from functools import wraps
from enum import Enum

PACKET_SIZE = 4096
MAX_ATTEMPTS = 3


def expect_ack(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.no_ack:
            func(self, *args, **kwargs)
        else:
            # handle ack
            attempts = 0
            pkt_ack = False
            while not pkt_ack and attempts != MAX_ATTEMPTS:
                func(self, *args, **kwargs)
                # read ack
                c_ack = self.sock.recv(1)
                if re.match(b'\+', c_ack):
                    self.log.debug('send: ack')
                    pkt_ack = True
                if re.match(b'-', c_ack):
                    self.log.debug('send: retransmit')
                    func(self, *args, **kwargs)
                    attempts += 1
            if not pkt_ack:
                raise RuntimeError('send: max attempt to send packet')
    return wrapper


class GDBSignal(Enum):
    TRAP = 5


class GDBCmd(Enum):
    GEN_QUERY_GET = 'q'
    GEN_QUERY_SET = 'Q'
    SET_THREAD_ID = 'H'
    TARGET_STATUS = '?'
    READ_REGISTERS = 'g'
    WRITE_REGISTERS = 'G'
    DETACH = 'D'
    READ_MEMORY = 'm'
    WRITE_MEMORY= 'M'
    CONTINUE = 'c'
    BREAKIN = '\x03'


class ChecksumError(Exception):
    pass


class GDBPacket():

    def __init__(self, packet_data):
        self.packet_data = packet_data

    def to_bytes(self):
        checksum = sum(self.packet_data) % 256
        header = b'$'
        footer = b'#'
        checksum_str = b'%.2x' % checksum
        sequence = (header, self.packet_data, footer, checksum_str)
        return b''.join(sequence)


class GDBStub():

    def __init__(self, conn, addr):
        _, client_port = addr
        self.log = logging.getLogger('client-{}'.format(client_port))
        self.sock = conn
        self.addr = addr
        self.sock.setblocking(True)
        self.no_ack = False
        self.attached = True
        self.buffer = b''
        self.last_pkt = None
        self.cmd_to_handler = {}
        self.cur_tid = 0

    def read_packet(self):
        epoll = select.epoll()
        epoll.register(self.sock.fileno(),  select.EPOLLIN | select.EPOLLHUP | select.EPOLLRDHUP)
        while self.attached:
            events = epoll.poll()
            for fileno, event in events:
                if fileno == self.sock.fileno():
                    if event == select.EPOLLIN:
                        self.buffer += self.sock.recv(PACKET_SIZE)
                    if event == select.EPOLLHUP:
                        self.log.debug('EPOLLHUP')
                    if event == select.EPOLLRDHUP:
                        self.log.debug('EPOLLRDHUP')
                else:
                    raise RuntimeError('unknown fd %d', fileno)
            # CTRL-C ?
            m = re.match(b'\x03', self.buffer)
            if m:
                self.buffer = self.buffer[1:]
                # create a normal packet to let stub call a handler
                return b'\x03'
            # packet ?
            m = re.match(b'\$(?P<data>.*)#(?P<checksum>..)', self.buffer)
            if m:
                packet_data = m.group('data')
                packet_checksum = int(m.group('checksum'), 16)
                if not self.no_ack:
                    self.validate_packet(packet_data, packet_checksum)
                self.buffer = self.buffer[m.endpos+1:]
                return packet_data
            # not enough packet data to match a packet regex

    def validate_packet(self, packet_data, packet_checksum):
        checksum = sum(packet_data) % 256
        if checksum != packet_checksum:
            raise ChecksumError('invalid checksum received')

    def send_msg(self, msg):
        self.log.debug('send: %s', msg)
        self.sock.sendall(msg)

    @expect_ack
    def send_packet(self, pkt):
        self.send_msg(pkt.to_bytes())

    def handle_rsp(self):
        self.log.info('connected')

        # read first ack
        c_ack = self.sock.recv(1)
        if not re.match(b'\+', c_ack):
            raise RuntimeError('Fail to receive first ack')

        while self.attached:
            packet_data = None
            try:
                packet_data = self.read_packet()
            except ChecksumError:
                # ask to resend packet
                self.log.debug('invalid checksum')
                self.send_msg(b'-')
            else:
                self.log.info('new packet: %s', packet_data)
                if not self.no_ack:
                    self.send_msg(b'+')

            self.call_handler(packet_data)
        # close socket
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def call_handler(self, packet_data):
        cmd, cmd_data = chr(packet_data[0]), packet_data[1:]
        try:
            handler = self.cmd_to_handler[GDBCmd(cmd)]
        except (ValueError, KeyError):
            self.log.info('unknown command {}'.format(cmd))
            self.send_packet(GDBPacket(b''))
        else:
            handled = handler(cmd_data)
            if not handled:
                self.log.info('command %s: FAIL', cmd)
                self.send_packet(GDBPacket(b''))
            else:
                self.log.info('command %s: DONE', cmd)
