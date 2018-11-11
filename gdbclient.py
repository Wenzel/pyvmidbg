import logging
import re
import struct
import select

PACKET_SIZE = 4096

class ChecksumError(Exception):
    pass


class GDBPacket():

    def __init__(self, packet_data):
        self.packet_data = packet_data

    def to_bytes(self):
        checksum = sum(self.packet_data) % 256
        header = b'$'
        footer = b'#'
        checksum_str = b'%x' % checksum
        sequence = (header, self.packet_data, footer, checksum_str)
        return b''.join(sequence)


class GDBClient():

    def __init__(self, conn, addr):
        self.log = logging.getLogger('client')
        self.sock = conn
        self.addr = addr
        self.sock.setblocking(True)
        self.fsock = self.sock.makefile(mode='rw')
        self.buffer = b''
        self.last_pkt = None

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
                            self.log.debug('buffer: %s', self.buffer)
                        if event == select.EPOLLHUP:
                            self.log.debug('EPOLLHUP')
                        if event == select.EPOLLRDHUP:
                            self.log.debug('EPOLLRDHUP')
                    else:
                        raise RuntimeError('unknown fd %d', fileno)
            # ack ok ?
            m = re.match(b'\+', self.buffer)
            if m:
                self.log.debug('acknowledged')
                self.buffer = self.buffer[1:]
                continue
            m = re.match(b'-', self.buffer)
            # ack retransmit
            if m:
                self.log.debug('retransmit last packet')
                self.buffer = self.buffer[1:]
                if self.last_pkt is None:
                    raise RuntimeError('no last packet to retransmit')
                self.send_packet(self.last_pkt)
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
            self.log.info('buffer data: %s', self.buffer)
            # not enough packet data to match a packet regex
            raise RuntimeError('not implemented')

    def validate_packet(self, packet_data, packet_checksum):
        checksum = sum(packet_data) % 256
        if checksum != packet_checksum:
            raise ChecksumError('invalid checksum received')

    def send_msg(self, msg):
        self.sock.sendall(msg)

    def send_packet(self, pkt):
        self.last_pkt = pkt
        reply = pkt.to_bytes()
        self.log.debug('reply: %s', reply)
        self.send_msg(pkt.to_bytes())

    def handle_rsp(self):
        self.log.info('connected')

        while True:
            packet_data = None
            try:
                packet_data = self.read_packet()
            except ChecksumError:
                # ask to resend packet
                self.log.debug('invalid checksum')
                self.send_msg(b'-')
            else:
                self.log.info('new packet: %s', packet_data)
                self.send_msg(b'+')

            self.cmd_dispatcher(packet_data)

    def cmd_dispatcher(self, packet_data):
        cmd, cmd_data = chr(packet_data[0]), packet_data[1:]
        try:
            handler_name = 'cmd_{}'.format(cmd)
            self.log.info('trying handler {}'.format(handler_name))
            handler = getattr(self, handler_name)
            handler(cmd_data)
        except AttributeError:
            self.log.info('unhandled command {}'.format(cmd))
