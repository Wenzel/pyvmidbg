import logging

from libvmi import LibvmiError, X86Reg, AccessContext, TranslateMechanism

class RawDebugContext:

    def __init__(self, vmi):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi

    def attach(self):
        self.log.info('attaching on %s', self.vmi.get_name())
        self.vmi.pause_vm()

    def detach(self):
        logging.info('detaching from %s', self.vmi.get_name())
        try:
            self.vmi.resume_vm()
        except LibvmiError:
            # already in running state
            pass

    def get_dtb(self):
        # get current CR3
        return self.vmi.get_vcpu_reg(X86Reg.CR3.value, 0)

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_DTB,
                             addr=address, dtb=self.get_dtb())