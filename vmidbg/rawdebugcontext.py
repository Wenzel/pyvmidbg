import logging

from libvmi import LibvmiError, X86Reg, AccessContext, TranslateMechanism


class RawThread:

    def __init__(self, id):
        self.id = id

    def is_alive(self):
        # always alive, it's a VCPU
        return True


class RawDebugContext:

    def __init__(self, vmi):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        # create threads
        self.threads = []
        for i in range(0, self.vmi.get_num_vcpus()):
            self.threads.append(RawThread(i+1))
        self.cur_tid_idx = 0

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

    def list_threads(self):
        return self.threads

    def get_current_thread(self):
        return self.threads[self.cur_tid_idx]