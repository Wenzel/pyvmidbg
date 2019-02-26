import logging
import json
import re
import struct
from enum import Enum

from libvmi import AccessContext, TranslateMechanism, X86Reg, VMIWinVer
from libvmi.event import RegEvent, RegAccess


class ThreadState(Enum):
    INITIALIZED = 0
    READY = 1
    RUNNING = 2
    STANDBY = 3
    TERMINATED = 4
    WAIT = 5
    TRANSITION = 6
    UNKNOWN = 7


class WindowsThread:

    def __init__(self, thread_list_entry, vmi, rekall):
        self.vmi = vmi
        self.rekall = rekall
        self.rekall_thread = self.rekall['$STRUCTS']['_ETHREAD'][1]
        unique_thread_off = self.rekall['$STRUCTS']['_CLIENT_ID'][1]['UniqueThread'][0]
        self.addr = thread_list_entry - self.rekall_thread['ThreadListEntry'][0]
        self.id = self.vmi.read_addr_va(self.addr + self.rekall_thread['Cid'][0] + unique_thread_off, 0)
        self.next_entry = self.vmi.read_addr_va(self.addr + self.rekall_thread['ThreadListEntry'][0], 0)
        self.start_addr = self.vmi.read_addr_va(self.addr + self.rekall_thread['StartAddress'][0], 0)
        self.win32_start_addr = self.vmi.read_addr_va(self.addr + self.rekall_thread['Win32StartAddress'][0], 0)

        self.State = ThreadState(int.from_bytes(self.read_field('State', '_KTHREAD'), byteorder='little'))

    def read_field(self, field_name, struct_name='_ETHREAD'):
        field_info = self.rekall['$STRUCTS'][struct_name][1][field_name]
        offset, data_type = field_info
        # ignore target
        data_type = data_type[0]
        format = None
        if data_type == 'unsigned char':
            format = 'B'
        count = struct.calcsize(format)
        buffer, bytes_read = self.vmi.read_va(self.addr + offset, 0, count)
        if bytes_read != count:
            raise RuntimeError('Failed to read field')
        return buffer

    def is_alive(self):
        return True

    def __str__(self):
        return "[{}] - addr: {}, start_address: {}, state: {}"\
            .format(self.id, hex(self.addr), hex(self.start_addr), self.State.name)


class WindowsTaskDescriptor:

    def __init__(self, task_addr, vmi, rekall):
        self.vmi = vmi
        self.rekall = rekall
        self.rekall_task = self.rekall['$STRUCTS']['_EPROCESS'][1]
        self.addr = task_addr - self.vmi.get_offset('win_tasks')
        self.dtb = self.vmi.read_32_va(self.addr + self.vmi.get_offset('win_pdbase'), 0)
        self.pid = self.vmi.read_32_va(self.addr + self.vmi.get_offset('win_pid'), 0)
        self.name = self.vmi.read_str_va(self.addr + self.vmi.get_offset('win_pname'), 0)
        self.thread_head = self.addr + self.rekall_task['ThreadListHead'][0]
        self.thread_head_entry = self.vmi.read_addr_va(self.addr + self.rekall_task['ThreadListHead'][0], 0)
        self.next_task = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('win_tasks'), 0)
        self.next_desc = self.next_task - self.vmi.get_offset('win_tasks')

    def list_threads(self):
        thread_list_entry = self.thread_head_entry
        while True:
            desc = WindowsThread(thread_list_entry, self.vmi, self.rekall)
            yield desc
            # read next thread
            thread_list_entry = desc.next_entry
            if thread_list_entry == self.thread_head:
                break

    def __str__(self):
        return "[{}] {} {}".format(self.pid, self.name, hex(self.addr))


class WindowsDebugContext:

    def __init__(self, vmi, process):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        self.rekall = None
        with open(self.vmi.get_rekall_path()) as f:
            self.rekall = json.load(f)
        self.process = process
        self.target_name = process
        self.target_desc = None
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
            self.log.info('kernel base: %s', hex(ps_head_va - ps_head_rva))

    def attach(self):
        # 1 - pause to get a consistent memory access
        self.vmi.pause_vm()
        # 2 - find our target name in process list
        # process name might include regex chars
        pattern = re.escape(self.target_name)
        found = [desc for desc in self.list_processes() if re.match(pattern, desc.name)]
        if not found:
            self.log.debug('%s not found in process list:', self.target_name)
            for desc in self.list_processes():
                self.log.debug(desc)
            raise RuntimeError('Could not find process')
        if len(found) > 1:
            self.log.warning('Found %s processes matching "%s", picking the first match ([%s])',
                             len(found), self.target_name, found[0].pid)
        self.target_desc = found[0]
        self.log.info('Process: {}'.format(self.target_desc))
        # 4 - enumerate threads
        for thread in self.list_threads():
            self.log.info('Thread: {}'.format(thread))

    def list_processes(self):
        head_task = self.vmi.translate_ksym2v('PsActiveProcessHead')
        task_addr = self.vmi.read_addr_va(head_task, 0)
        while True:
            desc = WindowsTaskDescriptor(task_addr, self.vmi, self.rekall)
            yield desc
            # read next task
            task_addr = desc.next_task
            if task_addr == head_task:
                break
        # Idle process ? (Window XP)
        if self.vmi.get_winver() == VMIWinVer.OS_WINDOWS_XP:
            idle_desc_addr = self.vmi.read_addr_ksym('PsIdleProcess')
            desc = WindowsTaskDescriptor(idle_desc_addr + self.vmi.get_offset('win_tasks'), self.vmi,
                                         self.rekall)
            yield desc

    def list_threads(self):
        return self.target_desc.list_threads()

    def get_current_thread(self):
        return next(self.target_desc.list_threads())

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_PID,
                             addr=address, pid=self.target_desc.pid)

    def get_dtb(self):
        return self.target_desc.dtb

    def detach(self):
        self.vmi.resume_vm()
