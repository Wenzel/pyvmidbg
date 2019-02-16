import logging
import json
import re

from libvmi import AccessContext, TranslateMechanism, X86Reg, VMIWinVer
from libvmi.event import RegEvent, RegAccess


class WindowsThread:

    def __init__(self, id):
        self.id = id

    def is_alive(self):
        return True


class WindowsTaskDescriptor:

    def __init__(self, task_addr, vmi):
        self.vmi = vmi
        self.addr = task_addr - self.vmi.get_offset('win_tasks')
        self.dtb = self.vmi.read_32_va(self.addr + self.vmi.get_offset('win_pdbase'), 0)
        self.pid = self.vmi.read_32_va(self.addr + self.vmi.get_offset('win_pid'), 0)
        self.name = self.vmi.read_str_va(self.addr + self.vmi.get_offset('win_pname'), 0)
        self.next_task = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('win_tasks'), 0)
        self.next_desc = self.next_task - self.vmi.get_offset('win_tasks')

    def __str__(self):
        return "[{}] {} @{}".format(self.pid, self.name, hex(self.addr))


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

        # 1 - pause to get a consistent memory access
        self.vmi.pause_vm()
        # 2 - find our target name in process list
        # process name might include regex chars
        pattern = re.escape(self.target_name)
        found = [desc for desc in self.list_processes() if re.match(pattern, desc.name)]
        if not found:
            logging.debug('%s not found in process list:', self.target_name)
            for desc in self.list_processes():
                logging.debug(desc)
            raise RuntimeError('Could not find process')
        if len(found) > 1:
            logging.warning('Found %s processes matching "%s", picking the first match ([%s])',
                            len(found), self.target_name, found[0].pid)
        self.target_desc = found[0]
        # 4 - wait for our process to be scheduled (CR3 load)
        cb_data = {
            'interrupted': False
        }

        def cb_on_cr3_load(vmi, event):
            found = [desc for desc in self.list_processes() if desc.dtb == event.cffi_event.reg_event.value]
            if not found:
                raise RuntimeError('Cannot find currently scheduled process')
            if len(found) > 2:
                raise RuntimeError('Found multiple tasks matching same DTB')
            desc = found[0]
            self.log.info('intercepted %s', desc.name)
            if desc.dtb == self.target_desc.dtb:
                vmi.pause_vm()
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

    def list_processes(self):
        head_task = self.vmi.translate_ksym2v('PsActiveProcessHead')
        task_addr = self.vmi.read_addr_va(head_task, 0)
        while True:
            desc = WindowsTaskDescriptor(task_addr, self.vmi)
            yield desc
            # read next task
            task_addr = desc.next_task
            if task_addr == head_task:
                break
        # Idle process ? (Window XP)
        if self.vmi.get_winver() == VMIWinVer.OS_WINDOWS_XP:
            idle_desc_addr = self.vmi.read_addr_ksym('PsIdleProcess')
            desc = WindowsTaskDescriptor(idle_desc_addr + self.vmi.get_offset('win_tasks'), self.vmi)
            yield desc

    def list_threads(self):
        return self.threads

    def get_current_thread(self):
        return self.threads[0]

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_PID,
                             addr=address, pid=self.target_desc.pid)

    def get_dtb(self):
        return self.target_desc.dtb

    def detach(self):
        self.vmi.resume_vm()
