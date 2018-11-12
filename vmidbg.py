#!/usr/bin/env python3

"""GDB server.

Usage:
  vmidbg.py <address> <port>
  vmidbg.py (-h | --help)
  vmidbg.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.

"""

import logging
import sys
import re
import struct
from binascii import hexlify
from docopt import docopt

from gdbserver import GDBServer
from gdbclient import GDBClient, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE

class LibVMIClient(GDBClient):

    def __init__(self, conn, addr):
        super().__init__(conn, addr)
        self.cmd_to_handler = {
            GDBCmd.CMD_Q: self.cmd_q,
            GDBCmd.CMD_H: self.cmd_H,
            GDBCmd.CMD_QMARK: self.cmd_qmark,
            GDBCmd.CMD_G: self.cmd_g
        }


    def cmd_q(self, packet_data):
        if re.match(b'Supported', packet_data):
            reply = b'PacketSize=%x' % PACKET_SIZE
            pkt = GDBPacket(reply)
            self.send_packet(pkt)
            return True
        if re.match(b'TStatus', packet_data):
            # Ask the stub if there is a trace experiment running right now
            # reply: No trace has been run yet
            self.send_packet(GDBPacket(b'T0;tnotrun:0'))
            return True
        if re.match(b'TfV', packet_data):
            # TODO
            return False
        if re.match(b'fThreadInfo', packet_data):
            self.send_packet(GDBPacket(b'm0'))
            return True
        if re.match(b'sThreadInfo', packet_data):
            # send end of thread list
            self.send_packet(GDBPacket(b'l'))
            return True
        if re.match(b'Attached', packet_data):
            # attach existing process: 0
            # attach new process: 1
            self.send_packet(GDBPacket(b'0'))
            return True
        if re.match(b'C', packet_data):
            # return current thread id
            self.send_packet(GDBPacket(b'QC%x' % self.cur_tid))
            return True
        return False

    def cmd_H(self, packet_data):
        m = re.match(b'(?P<op>[cg])(?P<tid>([0-9a-f])+|-1)', packet_data)
        if m:
            op = m.group('op')
            tid = int(m.group('tid'), 16)
            self.cur_tid = tid
            # TODO op, Enn
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def cmd_qmark(self, packet_data):
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

    def cmd_g(self, packet_data):
        # test data, 15 registers, 32 bits
        # eax -> edi (8 regs)
        registers = [x+1 for x in range(1, 9)]
        # eip, eflags (2 regs)
        registers.extend([x+1 for x in range(9, 11)])
        # ss -> gs (6 regs)
        registers.extend([x+1 for x in range(11, 17)])
        msg = b''
        for r in registers:
            msg += hexlify(struct.pack('@I', r))
        self.send_packet(GDBPacket(msg))
        return True

def main(args):
    address = args['<address>']
    port = int(args['<port>'])

    logging.basicConfig(level=logging.DEBUG)

    with GDBServer(address, port, client_cls=LibVMIClient) as server:
        server.listen()


if __name__ == "__main__":
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)