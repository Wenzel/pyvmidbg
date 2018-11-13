#!/usr/bin/env python3

"""LibVMI-based GDB server.

Usage:
  vmidbg.py [options] <port>
  vmidbg.py (-h | --help)

Options:
  -a ADDR, --address=<ADDR>     Server address to listen on [default: 127.0.0.1]
  -h --help                     Show this screen.
  --version                     Show version.

"""

import logging
from docopt import docopt

from .gdbserver import GDBServer
from .libvmistub import LibVMIStub


def main():
    args = docopt(__doc__)
    address = args['--address']
    port = int(args['<port>'])

    logging.basicConfig(level=logging.DEBUG)

    with GDBServer(address, port, stub_cls=LibVMIStub) as server:
        server.listen()


if __name__ == "__main__":
    main()
