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
from docopt import docopt

from gdbserver import GDBServer
from gdbclient import GDBClient

class LibVMIClient(GDBClient):

    def __init__(self, conn, addr):
        super().__init__(conn, addr)



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