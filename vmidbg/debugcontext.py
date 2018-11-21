import logging
import re
import json

from libvmi import Libvmi, LibvmiError, X86Reg, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import RegAccess, RegEvent


def dtb_to_pname(vmi, dtb):
    tasks_off = vmi.get_offset('win_tasks')
    pdb_off = vmi.get_offset('win_pdbase')
    name_off = vmi.get_offset('win_pname')
    ps_head = vmi.translate_ksym2v('PsActiveProcessHead')
    flink = vmi.read_addr_ksym('PsActiveProcessHead')

    while flink != ps_head:
        start_proc = flink - tasks_off
        value = vmi.read_addr_va(start_proc + pdb_off, 0)
        if value == dtb:
            return vmi.read_str_va(start_proc + name_off, 0)
        flink = vmi.read_addr_va(flink, 0)
    # idle process (winxp) ?
    start_proc = vmi.read_addr_ksym('PsIdleProcess')
    value = vmi.read_addr_va(start_proc + pdb_off, 0)
    if value == dtb:
        return vmi.read_str_va(start_proc + name_off, 0)
    raise RuntimeError('fail to find process name for dtb {}'.format(hex(dtb)))


class DebugContext:

    def __init__(self, vm_name, process_name):
        self.log = logging.getLogger(__class__.__name__)
        self.vm_name = vm_name
        self.target_name = process_name
        self.target_pid = None
        self.target_dtb = None
        self.vmi = Libvmi(self.vm_name, INIT_DOMAINNAME | INIT_EVENTS)
        self.kernel_base = self.get_kernel_base()
        logging.info('kernel base address: %s', hex(self.kernel_base))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        try:
            logging.info('resuming VM execution')
            self.vmi.resume_vm()
        except LibvmiError:
            # already in running state
            pass
        self.vmi.destroy()

    def get_kernel_base(self):
        # small hack with rekall JSON profile to get the kernel base address
        # LibVMI should provide an API to query it
        profile_path = self.vmi.get_rekall_path()
        if not profile_path:
            raise RuntimeError('Cannot get rekall profile from LibVMI')
        with open(profile_path) as f:
            profile = json.load(f)
            ps_head_rva = profile['$CONSTANTS']['PsActiveProcessHead']
            ps_head_va = self.vmi.translate_ksym2v('PsActiveProcessHead')
            return ps_head_va - ps_head_rva

    def attach(self):
        self.log.info('attaching on %s', self.target_name)
        # VM must be running
        self.vmi.pause_vm()

        cb_data = {
            'interrupted': False
        }

        def cb_on_cr3_load(vmi, event):
            pname = dtb_to_pname(vmi, event.cffi_event.reg_event.value)
            self.log.info('intercepted %s', pname)

            pattern = re.escape(self.target_name)
            if re.match(pattern, pname, re.IGNORECASE):
                vmi.pause_vm()
                self.target_dtb = event.cffi_event.reg_event.value
                self.target_pid = vmi.dtb_to_pid(self.target_dtb)
                cb_data['interrupted'] = True

        reg_event = RegEvent(X86Reg.CR3, RegAccess.W, cb_on_cr3_load)
        self.vmi.register_event(reg_event)
        self.vmi.resume_vm()

        while not cb_data['interrupted']:
            self.vmi.listen(1000)
        # clear queue
        self.vmi.listen(0)
        # clear event
        self.vmi.clear_event(reg_event)
