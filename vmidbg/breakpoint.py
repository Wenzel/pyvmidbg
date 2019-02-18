from libvmi import LibvmiError
from libvmi.event import SingleStepEvent

SW_BREAKPOINT = b'\xcc'

# TODO
# insert_xpoint
# remove_xpoint
# listen thread sync/async
# multiple bp at same address

class BreakpointError(Exception):
    pass

class BreakpointManager:

    def __init__(self, vmi, ctx):
        self.vmi = vmi
        self.ctx = ctx
        self.addr_to_opcode = {}

    def add_bp(self, addr, kind):
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

    def toggle_bp(self, addr, set):
        if set:
            buffer = SW_BREAKPOINT
        else:
            buffer = self.addr_to_opcode[addr]
        bytes_written = self.vmi.write(self.ctx.get_access_context(addr), buffer)
        if bytes_written < len(buffer):
            raise LibvmiError

    def singlestep_bp(self, addr):
        # disable breakpoint
        self.toggle_bp(addr, False)
        # singlestep
        self.singlestep_once()
        # enable breakpoint
        self.toggle_bp(addr, True)

    def continue_bp(self, addr):
        self.singlestep_bp(addr)
        self.vmi.resume_vm()

    def singlestep_once(self):

        cb_data = {
            'interrupted': False
        }

        def cb_on_sstep(vmi, event):
            self.vmi.pause_vm()
            cb_data['interrupted'] = True

        try:
            self.vmi.pause_vm()
        except LibvmiError:
            pass
        num_vcpus = self.vmi.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), cb_on_sstep)
        self.vmi.register_event(ss_event)
        self.vmi.resume_vm()
        while not cb_data['interrupted']:
            self.vmi.listen(1000)
        # clear queue
        self.vmi.listen(0)
        self.vmi.clear_event(ss_event)