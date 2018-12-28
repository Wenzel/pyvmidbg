#!/usr/bin/env python3

"""LibVMI-based GDB server.

Usage:
  vmidbg.py [options] <port> <vm_name> [<process>]
  vmidbg.py (-h | --help)

Options:
  -d --debug                    Enable debugging
  -a ADDR, --address=<ADDR>     Server address to listen on [default: 127.0.0.1]
  -h --help                     Show this screen.
  --version                     Show version.

"""

import logging
from docopt import docopt

from vmidbg.gdbserver import GDBServer
from vmidbg.libvmistub import LibVMIStub
from vmidbg.debugcontext import DebugContext


def main():
    args = docopt(__doc__)
    debug = args['--debug']
    address = args['--address']
    port = int(args['<port>'])
    vm_name = args['<vm_name>']
    process = args['<process>']

    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    with DebugContext(vm_name, process) as ctx:
        with GDBServer(address, port, stub_cls=LibVMIStub, stub_args=(ctx,)) as server:
            server.listen()

if __name__ == "__main__":
    main()
