import logging
import threading

from libvmi import LibvmiError
from libvmi.event import EventResponse, IntEvent, SingleStepEvent

SW_BREAKPOINT = b'\xcc'


class BreakpointError(Exception):
    pass


class BreakpointManager:

    def __init__(self, vmi, ctx):
        self.log = logging.getLogger(__class__.__name__)
        self.vmi = vmi
        self.ctx = ctx
        # register Int3 event
        self.int_event = IntEvent(self.cb_on_int3)
        self.vmi.register_event(self.int_event)
        # single step event to handle wrong hits by sw breakpoints
        # enabled via EventResponse.TOGGLE_SINGLESTEP
        num_vcpus = self.vmi.get_num_vcpus()
        self.sstep_recoil = SingleStepEvent(range(num_vcpus), self.cb_on_sstep_recoil, enable=False)
        self.vmi.register_event(self.sstep_recoil)
        self.listen_thread = None
        self.stop_listen = threading.Event()
        self.addr_to_opcode = {}
        self.handlers = {}
        # store the last addr where a swbreakpoint was hit
        # but it was not our targeted process
        # used in cb_on_sstep_recoil to restore the breakpoint after
        # the recoil
        self.last_addr_wrong_swbreak = None

    def restore_opcodes(self):
        for addr in self.addr_to_opcode.keys():
            self.toggle_bp(addr, False)

    def add_bp(self, addr, kind, callback, cb_data):
        # 1 - read opcode
        try:
            buffer, bytes_read = self.vmi.read(self.ctx.get_access_context(addr), kind)
        except LibvmiError:
            raise BreakpointError('Unable to read opcode')

        if bytes_read < kind:
            raise BreakpointError('Unable to read enough bytes')
        # 2 - save opcode
        self.addr_to_opcode[addr] = buffer
        # 3 - write breakpoint
        try:
            self.toggle_bp(addr, True)
        except LibvmiError:
            self.addr_to_opcode.pop(addr)
            raise BreakpointError('Unable to write breakpoint')
        else:
            # register callback
            self.handlers[addr] = (callback, cb_data)

    def del_bp(self, addr):
        # already removed ?
        if addr in self.addr_to_opcode:
            self.toggle_bp(addr, False)
            # remove callbacks
            del self.handlers[addr]

    def toggle_bp(self, addr, set):
        if set:
            buffer = SW_BREAKPOINT
        else:
            buffer = self.addr_to_opcode[addr]
        bytes_written = self.vmi.write(self.ctx.get_access_context(addr), buffer)
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
        # restore swbreak
        self.toggle_bp(self.last_addr_wrong_swbreak, True)
        self.last_addr_wrong_swbreak = None
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
        while not self.stop_listen.is_set():
            self.vmi.listen(1000)

    def cb_on_int3(self, vmi, event):
        addr = event.cffi_event.x86_regs.rip
        self.log.info('int3 hit %s', hex(addr))
        # set default reinject behavior
        event.reinject = 0
        # reinject ?
        if addr not in self.addr_to_opcode:
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
            callback, cb_data = self.handlers[addr]
        except KeyError:
            self.log.error('breakpoint handler not found !')
        else:
            event.data = cb_data
            need_sstep = callback(vmi, event)
            if need_sstep:
                # store current address to restore breakpoint in cb_sstep_recoil
                self.last_addr_wrong_swbreak = addr
                # restore original opcode
                self.toggle_bp(addr, False)
                # prepare to singlestep
                return EventResponse.TOGGLE_SINGLESTEP
