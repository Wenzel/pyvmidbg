import logging
import json
import re
from enum import Enum

from libvmi import AccessContext, TranslateMechanism, Registers, X86Reg, VMIWinVer, LibvmiError

from vmidbg.vmistruct import VMIStruct
from vmidbg.abstractdebugcontext import AbstractDebugContext
from vmidbg.gdbstub import GDBPacket, GDBSignal


class ThreadState(Enum):
    INITIALIZED = 0
    READY = 1
    RUNNING = 2
    STANDBY = 3
    TERMINATED = 4
    WAIT = 5
    TRANSITION = 6
    DEFERRED_READY = 7
    GATE_WAIT = 8


class WindowsThread:

    def __init__(self, thread_list_entry, vmi, rekall):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        self.rekall = rekall
        self.rekall_thread = self.rekall['$STRUCTS']['_ETHREAD'][1]
        self.addr = thread_list_entry - self.rekall_thread['ThreadListEntry'][0]
        self.ethread = VMIStruct(self.vmi, self.rekall['$STRUCTS'], '_ETHREAD', self.addr)
        self.id = self.ethread.Cid.UniqueThread
        self.next_entry = self.ethread.ThreadListEntry.Flink.addr
        self.start_addr = self.ethread.StartAddress
        self.win32_start_addr = self.ethread.Win32StartAddress

        self.kthread = self.ethread.Tcb
        self.State = ThreadState(self.kthread.State)
        # TODO reply contains invalid digit
        self.name = "0"

    def read_registers(self):
        self.log.debug('%s: read registers (state: %s)', self.id, self.State)
        if self.is_running():
            return self.vmi.get_vcpuregs(0)
        else:
            regs = Registers()
            if self.vmi.get_address_width() == 4:
                regs[X86Reg.RAX] = self.kthread.TrapFrame.Eax
                regs[X86Reg.RBX] = self.kthread.TrapFrame.Ebx
                regs[X86Reg.RCX] = self.kthread.TrapFrame.Ecx
                regs[X86Reg.RDX] = self.kthread.TrapFrame.Edx
                regs[X86Reg.RSI] = self.kthread.TrapFrame.Esi
                regs[X86Reg.RDI] = self.kthread.TrapFrame.Edi
                regs[X86Reg.RIP] = self.kthread.TrapFrame.Eip
                regs[X86Reg.RBP] = self.kthread.TrapFrame.Ebp
            else:
                regs[X86Reg.RAX] = self.kthread.TrapFrame.Rax
                regs[X86Reg.RBX] = self.kthread.TrapFrame.Rbx
                regs[X86Reg.RCX] = self.kthread.TrapFrame.Rcx
                regs[X86Reg.RDX] = self.kthread.TrapFrame.Rdx
                regs[X86Reg.RSI] = self.kthread.TrapFrame.Rsi
                regs[X86Reg.RDI] = self.kthread.TrapFrame.Rdi
                regs[X86Reg.RIP] = self.kthread.TrapFrame.Rip
                regs[X86Reg.RBP] = self.kthread.TrapFrame.Rbp
            regs[X86Reg.RSP] = self.kthread.KernelStack
            return regs

    def is_alive(self):
        return True

    def is_running(self):
        return self.State == ThreadState.RUNNING

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


class WindowsDebugContext(AbstractDebugContext):

    def __init__(self, vmi, process):
        super().__init__(vmi)
        self.log = logging.getLogger(__class__.__name__)
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
        # default thread: all threads
        self.cur_tid = -1

    def attach(self):
        # 1 - pause to get a consistent memory access
        self.vmi.pause_vm()
        # 2 - find our target name in process list
        # process name might include regex chars
        pattern = re.escape(self.target_name)
        found = [desc for desc in self.list_processes() if re.match(pattern, desc.name, re.IGNORECASE)]
        if not found:
            self.log.debug('%s not found in process list', self.target_name)
            self.attach_new_process()
        else:
            if len(found) > 1:
                self.log.warning('Found %s processes matching "%s", picking the first match ([%s])',
                                 len(found), self.target_name, found[0].pid)
            self.target_desc = found[0]
            self.log.info('Process: {}'.format(self.target_desc))
            # 4 - enumerate threads
            for thread in self.list_threads():
                self.log.info('Thread: {}'.format(thread))

    def attach_new_process(self):
        self.log.info('Waiting for %s process to start...', self.target_name)
        # get KiThreadStartup addr
        thread_startup_addr = self.vmi.translate_ksym2v('KiThreadStartup')
        self.log.debug('KiThreadStartup: %s', hex(thread_startup_addr))
        # continue to KithreadStartup
        self.bpm.continue_until(thread_startup_addr)
        # set target desc
        dtb = self.vmi.get_vcpu_reg(X86Reg.CR3.value, 0)
        self.target_desc = self.dtb_to_desc(dtb)
        # get ETHREAD.StartAddress address
        thread_desc = self.get_current_running_thread()
        thread_start_addr = thread_desc.start_addr
        self.log.debug('ETHREAD.StartAddress: %s', hex(thread_start_addr))
        # we cannot use inject a pagefault via our mov eax, [eax], for unclear reasons
        # the kernel will have a BSOD
        # I tested moving to PspUserThreadStartup to have a lower IRQL (APC_LEVEL)
        # doesn't work either
        # so find another process where ETHREAD.StartAddress is mapped
        # get paddr, and use this to place the breakpoint
        thread_start_paddr = None
        for desc in self.list_processes():
            try:
                dtb = desc.dtb
                self.log.info('Checking if addr is mapped in %s space', desc.name)
                thread_start_paddr = self.vmi.pagetable_lookup(dtb, thread_start_addr)
            except LibvmiError:
                self.log.info('Fail')
            else:
                self.log.info('Found at frame: %s', hex(thread_start_paddr))
                break

        self.bpm.continue_until(thread_start_addr, paddr=thread_start_paddr)
        if self.vmi.get_winver() == VMIWinVer.OS_WINDOWS_XP:
            # we are at BaseProcessStartThunk
            # read entrypoint address from EAX
            entrypoint_addr = self.vmi.get_vcpu_reg(X86Reg.RAX.value, 0)
            self.log.debug('Entrypoint: %s', hex(entrypoint_addr))
            # continue to entrypoint
            self.bpm.continue_until(entrypoint_addr)
        else:
            raise RuntimeError('Not implemented')

    def detach(self):
        self.vmi.resume_vm()

    def get_dtb(self):
        if not self.target_desc:
            return self.vmi.get_vcpu_reg(X86Reg.CR3.value, 0)
        else:
            return self.target_desc.dtb

    def dtb_to_desc(self, dtb):
        found = [desc for desc in self.list_processes() if desc.dtb == dtb]
        if not found:
            raise RuntimeError('Could not find task descriptor for DTB {}'.format(hex(dtb)))
        if len(found) > 1:
            self.log.warning('multiple processes matching same DTB !')
        desc = found[0]
        return desc

    def get_access_context(self, address):
        if self.target_desc is None:
            # PID 0 is kernel
            return AccessContext(TranslateMechanism.PROCESS_PID,
                                 addr=address, pid=0)
        else:
            return AccessContext(TranslateMechanism.PROCESS_PID,
                                 addr=address, pid=self.target_desc.pid)

    def get_current_running_thread(self):
        # TODO use KPCR
        found = [thread for thread in self.list_threads() if thread.State ==
                 ThreadState.RUNNING]
        if not found:
            self.log.warning('Cannot find current running thread')
            return None
        if len(found) > 1:
            self.log.warning('Multiple threads running')
        return found[0]

    def get_thread(self, tid=None):
        if not tid:
            tid = self.cur_tid
        if tid == -1 or tid == 0:
            # -1: indicate all threads
            # 0: pick any thread
            # return first one for now
            return next(self.list_threads())
        found = [thread for thread in self.list_threads() if thread.id == tid]
        if not found:
            self.log.warning('Cannot find thread ID %s', tid)
            return None
        if len(found) > 1:
            self.log.warning('Multiple threads sharing same id')
        return found[0]

    def list_threads(self):
        return self.target_desc.list_threads()

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

    def cb_on_swbreak(self, vmi, event):
        cb_data = event.data
        # check if it's our targeted process
        dtb = event.cffi_event.x86_regs.cr3
        if dtb != self.get_dtb():
            desc = self.dtb_to_desc(dtb)
            self.log.debug('wrong process: %s', desc.name)
            # need to singlestep
            return True
        else:
            self.log.debug('hit !')
            # pause
            self.vmi.pause_vm()
            cb_data['stop_listen'].set()
            thread = self.get_current_running_thread()
            if not thread:
                tid = -1
            else:
                tid = thread.id
            # report swbreak stop to client
            cb_data['stub'].send_packet_noack(GDBPacket(b'T%.2xswbreak:;thread:%x;' %
                                              (GDBSignal.TRAP.value, tid)))
            # don't singlestep
            return False
