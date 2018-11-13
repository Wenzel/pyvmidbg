import logging

from libvmi import Libvmi

class DebugContext:

    def __init__(self, vm_name):
        self.log = logging.getLogger(__class__.__name__)
        self.vm_name = vm_name
        self.process = None
        self.vmi = Libvmi(self.vm_name)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.vmi.destroy()

    def attach(self, process_name):
        self.log.info('attaching on %s', process_name)
        self.process_name = process_name
        # TODO dtb_to_pname
        # TODO dtb_to_pid_idle_extended