import logging
import re
import json
import struct

from libvmi import Libvmi, LibvmiError, X86Reg, VMIOS, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import RegAccess, RegEvent


def dtb_to_pname(vmi, dtb):
    if vmi.get_ostype() == VMIOS.WINDOWS:
        tasks_off = vmi.get_offset('win_tasks')
        pdb_off = vmi.get_offset('win_pdbase')
        name_off = vmi.get_offset('win_pname')
    elif vmi.get_ostype() == VMIOS.LINUX:
        tasks_off = vmi.get_offset('linux_tasks')
        pdb_off = vmi.get_offset('linux_pgd')
        name_off = vmi.get_offset('linux_name')
    else:
        raise RuntimeError('Unsupported OS')

    list_head = None
    if vmi.get_ostype() == VMIOS.WINDOWS:
        list_head = vmi.read_addr_ksym('PsActiveProcessHead')
    elif vmi.get_ostype() == VMIOS.LINUX:
        list_head = vmi.translate_ksym2v('init_task')
        list_head += tasks_off

    cur_list_entry = list_head
    next_list_entry = vmi.read_addr_va(cur_list_entry, 0)
    while True:
        start_proc = cur_list_entry - tasks_off
        if vmi.get_ostype() == VMIOS.WINDOWS:
            value = vmi.read_addr_va(start_proc + pdb_off, 0)
        elif vmi.get_ostype() == VMIOS.LINUX:
            # task_struct->mm->pgd->
            mm_off = vmi.get_offset('linux_mm')
            mm = vmi.read_addr_va(start_proc + mm_off, 0)
            if mm == 0:
                # kernel thread, no mm
                cur_list_entry = next_list_entry
                next_list_entry = vmi.read_addr_va(cur_list_entry, 0)
                continue
            pgd = vmi.read_addr_va(mm + pdb_off, 0)
            buffer, *rest = vmi.read_va(pgd, 0, 4)
            value, *rest = struct.unpack('@I', buffer)
        pname = vmi.read_str_va(start_proc + name_off, 0)
        if value == dtb:
            return vmi.read_str_va(start_proc + name_off, 0)
        cur_list_entry = next_list_entry
        next_list_entry = vmi.read_addr_va(cur_list_entry, 0)
        if vmi.get_ostype() == VMIOS.WINDOWS and next_list_entry == list_head:
            break
        if vmi.get_ostype() == VMIOS.LINUX and cur_list_entry == list_head:
            break
    # idle process (winxp) ?
    if vmi.get_ostype() == VMIOS.WINDOWS:
        start_proc = vmi.read_addr_ksym('PsIdleProcess')
        value = vmi.read_addr_va(start_proc + pdb_off, 0)
        if value == dtb:
            return vmi.read_str_va(start_proc + name_off, 0)
    raise RuntimeError('fail to find process name for dtb {}'.format(hex(dtb)))


class DebugContext:

    def __init__(self, vm_name, process_name):
        self.log = logging.getLogger(__class__.__name__)
        self.vm_name = vm_name
        self.full_system_mode = False
        self.target_name = process_name
        self.target_pid = None
        if process_name is None:
            self.full_system_mode = True
            self.target_name = 'kernel'
            # kernel space is represented by PID 0 in LibVMI
            self.target_pid = 0
        self.target_dtb = None
        self.vmi = Libvmi(self.vm_name, INIT_DOMAINNAME | INIT_EVENTS)
        self.kernel_base = self.get_kernel_base()
        if self.kernel_base:
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
        if self.vmi.get_ostype() == VMIOS.LINUX:
            return self.vmi.translate_ksym2v('start_kernel')
        if self.vmi.get_ostype() == VMIOS.WINDOWS:
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
        return None

    def attach(self):
        self.log.info('attaching on %s', self.target_name)
        # VM must be running
        self.vmi.pause_vm()
        if self.full_system_mode:
            # no need to intercept a specific process
            regs = self.vmi.get_vcpuregs(0)
            self.target_dtb = regs[X86Reg.CR3]
            return

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
