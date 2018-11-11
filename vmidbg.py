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
from docopt import docopt

from gdbserver import GDBServer
from gdbclient import GDBClient, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE

class LibVMIClient(GDBClient):

    def __init__(self, conn, addr):
        super().__init__(conn, addr)
        self.cmd_to_handler = {
            GDBCmd.CMD_Q: self.cmd_q,
            GDBCmd.CMD_H: self.cmd_H,
            GDBCmd.CMD_QMARK: self.cmd_qmark
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