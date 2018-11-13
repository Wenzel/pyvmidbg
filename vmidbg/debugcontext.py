import logging

from libvmi import Libvmi, LibvmiError, X86Reg, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import RegAccess, RegEvent


class DebugContext:

    def __init__(self, vm_name):
        self.log = logging.getLogger(__class__.__name__)
        self.vm_name = vm_name
        self.process = None
        self.vmi = Libvmi(self.vm_name, INIT_DOMAINNAME | INIT_EVENTS)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.vmi.resume_vm()
        except LibvmiError:
            # already in running state
            pass
        self.vmi.destroy()

    def attach(self, process_name):
        self.log.info('attaching on %s', process_name)
        self.process_name = process_name
        self.vmi.pause_vm()
        # TODO dtb_to_pid_idle_extended

        cb_data = {
            'interrupted': False,
            'counter': 0
        }

        def cb_on_cr3_load(vmi, event):
            cb_data['counter'] += 1
            self.log.debug('counter %d/500', cb_data['counter'])
            if cb_data['counter'] == 500:
                cb_data['interrupted'] = True

        reg_event = RegEvent(X86Reg.CR3, RegAccess.W, cb_on_cr3_load)
        self.vmi.register_event(reg_event)
        self.vmi.resume_vm()

        while not cb_data['interrupted']:
            self.vmi.listen(1000)
