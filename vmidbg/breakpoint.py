import logging
import threading
import re

from libvmi import LibvmiError, X86Reg
from libvmi.event import EventResponse, IntEvent, SingleStepEvent, DebugEvent, RegEvent, RegAccess

SW_BREAKPOINT = b'\xcc'


class BreakpointError(Exception):
    pass


class BreakpointManager:

    def __init__(self, vmi, ctx):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        self.ctx = ctx
        # register int3 event
        self.int_event = IntEvent(self.cb_on_int3)
        self.vmi.register_event(self.int_event)
        # register hardware debug event
        self.debug_event = DebugEvent(self.cb_on_debug)
        self.vmi.register_event(self.debug_event)
        # single step event to handle wrong hits by sw breakpoints
        # enabled via EventResponse.TOGGLE_SINGLESTEP
        num_vcpus = self.vmi.get_num_vcpus()
        self.sstep_recoil = SingleStepEvent(range(num_vcpus), self.cb_on_sstep_recoil, enable=False)
        self.vmi.register_event(self.sstep_recoil)
        self.listen_thread = None
        self.stop_listen = threading.Event()
        # handling software breakpoint
        self.swbp_addr_to_opcode = {}
        self.swbp_handlers = {}
        # handling hardware breakpoints
        self.hwbp_handlers = {}

    def restore_opcodes(self):
        for addr in self.swbp_addr_to_opcode.keys():
            self.toggle_swbp(addr, False)

    def add_swbp(self, addr, kind, callback, cb_data=None):
        if not self.ensure_pagedin(addr):
            # virtual address is not part of the process's VAD
            self.log.warning('Fail to add software breakpoint: addr not in VAD')
            return False
        # 1 - read opcode
        try:
            buffer, bytes_read = self.vmi.read(self.ctx.get_access_context(addr), kind)
        except LibvmiError:
            raise BreakpointError('Unable to read opcode')

        if bytes_read < kind:
            raise BreakpointError('Unable to read enough bytes')
        # 2 - save opcode
        self.swbp_addr_to_opcode[addr] = buffer
        # 3 - write breakpoint
        try:
            self.toggle_swbp(addr, True)
        except LibvmiError:
            self.swbp_addr_to_opcode.pop(addr)
            raise BreakpointError('Unable to write breakpoint')
        else:
            # register callback
            self.swbp_handlers[addr] = (callback, cb_data)

    def add_swbp_paddr(self, vaddr, paddr, kind, callback, cb_data=None):
        # 1 - read opcode
        try:
            buffer, bytes_read = self.vmi.read_pa(paddr, 1)
        except LibvmiError:
            raise BreakpointError('Unable to read opcode')

        if bytes_read < kind:
            raise BreakpointError('Unable to read enough bytes')
        # 2 - save opcode
        self.swbp_addr_to_opcode[vaddr] = buffer
        # 3 - write breakpoint
        try:
            self.toggle_swbp_paddr(paddr, True)
        except LibvmiError:
            self.swbp_addr_to_opcode.pop(vaddr)
            raise BreakpointError('Unable to write breakpoint')
        else:
            # register callback
            self.swbp_handlers[vaddr] = (callback, cb_data)

    def del_swbp(self, addr):
        # already removed ?
        if addr in self.swbp_addr_to_opcode:
            self.toggle_swbp(addr, False)
            # remove callbacks
            del self.swbp_handlers[addr]
            # remove opcode
            del self.swbp_addr_to_opcode[addr]

    def add_hwbp(self, addr, callback, cb_data=None):
        # set DR0 to RtlUserThreadStart
        self.vmi.set_vcpureg(addr, X86Reg.DR0.value, 0)
        # enable breakpoint in DR7
        self.toggle_dr0(True)
        # add callback to handlers
        self.hwbp_handlers[addr] = (callback, cb_data)

    def del_hwbp(self, addr):
        # disable breakpoint in DR7
        self.toggle_dr0(False)
        # clear breakpoint in DR0
        self.vmi.set_vcpureg(0, X86Reg.DR0.value, 0)
        try:
            del self.hwbp_handlers[addr]
        except KeyError:
            pass

    def toggle_swbp(self, addr, set):
        if set:
            buffer = SW_BREAKPOINT
        else:
            buffer = self.swbp_addr_to_opcode[addr]
        bytes_written = self.vmi.write(self.ctx.get_access_context(addr), buffer)
        if bytes_written < len(buffer):
            raise LibvmiError

    def toggle_swbp_paddr(self, paddr, set):
        if set:
            buffer = SW_BREAKPOINT
        else:
            buffer = self.swbp_addr_to_opcode[paddr]
        bytes_written = self.vmi.write_pa(paddr, buffer)
        if bytes_written < len(buffer):
            raise LibvmiError

    def singlestep_once(self):
        # unregister sstep_recoil
        self.vmi.clear_event(self.sstep_recoil)

        stop_event = threading.Event()

        def cb_on_sstep(vmi, event):
            self.vmi.pause_vm()
            stop_event.set()

        try:
            self.vmi.pause_vm()
        except LibvmiError:
            pass
        # register sstep
        num_vcpus = self.vmi.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), cb_on_sstep)
        self.vmi.register_event(ss_event)
        # resume and listen
        self.vmi.resume_vm()
        while not stop_event.is_set():
            self.vmi.listen(1000)
        # clear queue
        self.vmi.listen(0)
        self.vmi.clear_event(ss_event)

        # reregister sstep_recoil
        self.vmi.register_event(self.sstep_recoil)

    def cb_on_sstep_recoil(self, vmi, event):
        self.log.debug('recoil')
        cb_data = event.data
        if cb_data['reason'] == 'swbreak':
            # restore swbreak
            addr = cb_data['breakpoint']
            self.toggle_swbp(addr, True)
        elif cb_data['reason'] == 'hwbreak':
            # restore hwbreak
            self.toggle_dr0(True)
        else:
            raise RuntimeError('Unknown recoil reason: %s', cb_data['reason'])
        # done singlestepping
        return EventResponse.TOGGLE_SINGLESTEP

    def listen(self, block=True):
        self.listen_thread = threading.Thread(target=self.listen_func)
        self.listen_thread.start()
        if block:
            self.listen_thread.join()

    def stop_listening(self):
        self.stop_listen.set()
        if self.listen_thread:
            self.listen_thread.join()

    def listen_func(self):
        self.stop_listen.clear()
        while not self.stop_listen.is_set():
            self.vmi.listen(1000)

    def cb_on_int3(self, vmi, event):
        addr = event.cffi_event.x86_regs.rip
        self.log.info('int3 hit %s', hex(addr))
        # set default reinject behavior
        event.reinject = 0
        # reinject ?
        if addr not in self.swbp_addr_to_opcode:
            # not our breakpoint, reinject
            self.log.debug('reinject')
            event.reinject = 1
            return EventResponse.NONE
        # invalidate libvmi caches
        self.vmi.v2pcache_flush()
        self.vmi.pidcache_flush()
        self.vmi.rvacache_flush()
        self.vmi.symcache_flush()
        # call handlers
        try:
            callback, cb_data = self.swbp_handlers[addr]
        except KeyError:
            self.log.error('breakpoint handler not found !')
        else:
            event.data = cb_data
            need_sstep = callback(vmi, event)
            if need_sstep:
                # restore original opcode
                self.toggle_swbp(addr, False)
                # prepare to singlestep
                self.sstep_recoil.data = {
                    'reason': 'swbreak',
                    'breakpoint': addr,
                }
                return EventResponse.TOGGLE_SINGLESTEP

    def cb_on_debug(self, vmi, event):
        addr = event.cffi_event.x86_regs.rip
        self.log.info('debug hit %s', hex(addr))
        # set default reinject behavior
        event.reinject = 0
        # reinject ?
        if addr not in self.hwbp_handlers:
            # not our breakpoint, reinject
            self.log.debug('reinject')
            event.reinject = 1
            return EventResponse.NONE
        # invalidate libvmi caches
        self.vmi.v2pcache_flush()
        self.vmi.pidcache_flush()
        self.vmi.rvacache_flush()
        self.vmi.symcache_flush()
        # call handlers
        try:
            callback, cb_data = self.hwbp_handlers[addr]
        except KeyError:
            self.log.error('breakpoint handler not found !')
        else:
            event.data = cb_data
            need_sstep = callback(vmi, event)
            if need_sstep:
                # disable breakpoint
                self.toggle_dr0(False)
                # clear dr6
                self.vmi.set_vcpu_reg(0, X86Reg.DR6, 0)
                # prepare to singlestep
                self.sstep_recoil.data = {
                    'reason': 'hwbreak',
                    'breakpoint': addr,
                }
                return EventResponse.TOGGLE_SINGLESTEP
            # clear dr6
            self.vmi.set_vcpureg(0, X86Reg.DR6.value, 0)

    def toggle_dr0(self, enabled):

        def set_bit(value, index, enabled):
            mask = 1 << index
            if enabled:
                value |= mask
            else:
                value &= ~mask
            return value
        # read old DR7 value
        dr7_value = self.vmi.get_vcpu_reg(X86Reg.DR7.value, 0)
        new_value = set_bit(dr7_value, 1, enabled)
        self.vmi.set_vcpureg(new_value, X86Reg.DR7.value, 0)

    def continue_until(self, addr, hwbreakpoint=False, paddr=False):
        # 1 - define handler
        def handle_breakpoint(vmi, event):
            # find current process
            dtb = event.cffi_event.x86_regs.cr3
            desc = self.ctx.dtb_to_desc(dtb)
            pattern = re.escape(self.ctx.target_name)
            if not re.match(pattern, desc.name, re.IGNORECASE):
                self.log.info('wrong process: %s', desc.name)
                # need to singlestep
                return True
            else:
                self.stop_listen.set()
                self.vmi.pause_vm()
                # don't singlestep
                return False

        # 2 - set a breakpoint
        if hwbreakpoint:
            self.add_hwbp(addr, handle_breakpoint)
        else:
            if paddr:
                self.add_swbp_paddr(addr, paddr, 1, handle_breakpoint)
            else:
                self.add_swbp(addr, 1, handle_breakpoint)
        # 3 - wait for hit
        self.vmi.resume_vm()
        self.stop_listen.clear()
        self.listen(block=True)
        # 4 - remove our breakpoint
        if hwbreakpoint:
            self.del_hwbp(addr)
        else:
            self.del_swbp(addr)

    # pagefault injection
    def ensure_pagedin(self, addr):
        """
        Ensure that a given virtual address has a frame in physical memory
        """
        dtb = self.ctx.get_dtb()
        try:
            self.vmi.pagetable_lookup(dtb, addr)
        except LibvmiError:
            # paged out !
            logging.warning('%s is paged out !', hex(addr))
            self.inject_pagefault(addr)
            return True
        else:
            return True
        return False

    def inject_pagefault(self, addr):
        """
        inject a shellcode that will trigger a memory access in the guest,
        and let the guest recover from the pagefault to remap the missing frame in
        physical memory
        :param addr:
        :return:
        """
        # prepare shellcode
        # mov eax, [eax]
        # 0x8B 0x00
        shellcode = b'\x8B\x00'
        # save registers
        logging.debug('save registers')
        orig_regs = self.vmi.get_vcpuregs(0)
        # save original instructions at current rip
        logging.debug('save original instructions')
        acc_ctx = self.ctx.get_access_context(orig_regs[X86Reg.RIP])
        count = len(shellcode)
        orig_opcodes, *rest = self.vmi.read(acc_ctx, count)
        # set eax as our faulty address
        logging.debug('set eax as our faulty address')
        self.vmi.set_vcpureg(addr, X86Reg.RAX.value, 0)
        # inject shellcode
        logging.debug('write shellcode')
        self.vmi.write(acc_ctx, shellcode)
        # continue until after shellcode
        logging.debug('continue after shellcode')
        after_shellcode_addr = orig_regs[X86Reg.RIP] + len(shellcode)
        self.continue_until(after_shellcode_addr)
        # restore registers
        logging.debug('restore registers')
        self.vmi.set_vcpuregs(orig_regs, 0)
        # restore instructions
        logging.debug('restore original instructions')
        self.vmi.write(acc_ctx, orig_opcodes)
        # confirm that our address is pagedin now
        dtb = self.ctx.get_dtb()
        try:
            self.vmi.pagetable_lookup(dtb, addr)
        except LibvmiError as e:
            raise RuntimeError('pagefault injection failed !') from e
        else:
            logging.info('pagefault injection succeeded !')

    def wait_process_scheduled(self):
        # current thread already scheduled ?
        thread = self.ctx.get_thread()
        if thread.is_running():
            return
        self.log.info('Waiting for thread %s to be scheduled', hex(thread.id))

        def handle_breakpoint(vmi, event):
            self.stop_listen.set()
        # set a breakpoint on thread rip
        regs = thread.read_registers()
        self.continue_until(regs[X86Reg.RIP])
