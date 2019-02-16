import logging
import json

from libvmi import AccessContext, TranslateMechanism


class WindowsThread:

    def __init__(self, id):
        self.id = id

    def is_alive(self):
        return True


class WindowsDebugContext:

    def __init__(self, vmi, process):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        self.process = process
        self.target_name = process
        self.target_desc = None
        self.threads = [WindowsThread(1)]
        # misc: print kernel base address
        # small hack with rekall JSON profile to get the kernel base address
        # LibVMI should provide an API to query it
        profile_path = self.vmi.get_rekall_path()
        if not profile_path:
            raise RuntimeError('Cannot get rekall profile from LibVMI')
        with open(profile_path) as f:
            profile = json.load(f)
            ps_head_rva = profile['$CONSTANTS']['PsActiveProcessHead']
            ps_head_va = self.vmi.translate_ksym2v('PsActiveProcessHead')
            self.log.info('kernel base: @%s', hex(ps_head_va - ps_head_rva))

    def attach(self):
        raise RuntimeError('Not implemented')

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_PID,
                             addr=address, pid=self.target_desc.pid)

    def detach(self):
        raise RuntimeError('Not implemented')