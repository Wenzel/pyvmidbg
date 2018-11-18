import logging
import re
import struct
import sys
from binascii import hexlify, unhexlify

from libvmi import LibvmiError, X86Reg, Registers
from libvmi.event import SingleStepEvent

from .gdbstub import GDBStub, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE


class LibVMIStub(GDBStub):

    def __init__(self, conn, addr, debug_ctx):
        super().__init__(conn, addr)
        self.ctx = debug_ctx
        self.cmd_to_handler = {
            GDBCmd.GEN_QUERY_GET: self.gen_query_get,
            GDBCmd.GEN_QUERY_SET: self.gen_query_set,
            GDBCmd.SET_THREAD_ID: self.set_thread_id,
            GDBCmd.TARGET_STATUS: self.target_status,
            GDBCmd.READ_REGISTERS: self.read_registers,
            GDBCmd.WRITE_REGISTERS: self.write_registers,
            GDBCmd.DETACH: self.detach,
            GDBCmd.READ_MEMORY: self.read_memory,
            GDBCmd.WRITE_MEMORY: self.write_memory,
            GDBCmd.CONTINUE: self.cont_execution,
            GDBCmd.SINGLESTEP: self.singlestep,
            GDBCmd.BREAKIN: self.breakin
        }


    def gen_query_get(self, packet_data):
        if re.match(b'Supported', packet_data):
            reply = b'PacketSize=%x' % PACKET_SIZE
            pkt = GDBPacket(reply)
            self.send_packet(pkt)
            return True
        if re.match(b'TStatus', packet_data):
            # Ask the stub if there is a trace experiment running right now
            # reply: No trace has been run yet
            self.send_packet(GDBPacket(b'T0;tnotrun:0'))
            return True
        if re.match(b'TfV', packet_data):
            # TODO
            return False
        if re.match(b'fThreadInfo', packet_data):
            self.send_packet(GDBPacket(b'm0'))
            return True
        if re.match(b'sThreadInfo', packet_data):
            # send end of thread list
            self.send_packet(GDBPacket(b'l'))
            return True
        if re.match(b'Attached', packet_data):
            # attach existing process: 0
            # attach new process: 1
            self.send_packet(GDBPacket(b'0'))
            return True
        if re.match(b'C', packet_data):
            # return current thread id
            self.send_packet(GDBPacket(b'QC%x' % self.cur_tid))
            return True
        return False

    def gen_query_set(self, packet_data):
        if re.match(b'StartNoAckMode', packet_data):
            self.no_ack = True
            self.send_packet(GDBPacket(b'OK'))
            # read last ack
            c = self.sock.recv(1)
            if c == b'+':
                return True
            else:
                return False
        return False

    def set_thread_id(self, packet_data):
        m = re.match(b'(?P<op>[cg])(?P<tid>([0-9a-f])+|-1)', packet_data)
        if m:
            op = m.group('op')
            tid = int(m.group('tid'), 16)
            self.cur_tid = tid
            # TODO op, Enn
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def target_status(self, packet_data):
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

    def read_registers(self, packet_data):
        addr_width = self.ctx.vmi.get_address_width()
        if addr_width == 4:
            pack_fmt = '@I'
        else:
            pack_fmt = '@Q'

        # TODO VCPU 0
        regs = self.ctx.vmi.get_vcpuregs(0)
        gen_regs_32 = [
            X86Reg.RAX, X86Reg.RCX, X86Reg.RDX, X86Reg.RBX,
            X86Reg.RSP, X86Reg.RBP, X86Reg.RSI, X86Reg.RDI, X86Reg.RIP
        ]

        gen_regs_64 = [
            X86Reg.R9, X86Reg.R10, X86Reg.R11, X86Reg.R12,
            X86Reg.R13, X86Reg.R14, X86Reg.R15
        ]
        # not available through libvmi
        seg_regs = [x+1 for x in range(0, 6)]
        # write general registers
        msg = b''.join([hexlify(struct.pack(pack_fmt, regs[r])) for r in gen_regs_32])
        if addr_width == 8:
            msg += b''.join([hexlify(struct.pack(pack_fmt, regs[r])) for r in gen_regs_64])
        # write eflags
        msg += hexlify(struct.pack(pack_fmt, regs[X86Reg.RFLAGS]))
        # write segment registers
        msg += b''.join([hexlify(struct.pack(pack_fmt, r)) for r in seg_regs])
        self.send_packet(GDBPacket(msg))
        return True

    def write_registers(self, packet_data):
        addr_width = self.ctx.vmi.get_address_width()
        if addr_width == 4:
            pack_fmt = '@I'
        else:
            pack_fmt = '@Q'
        gen_regs_32 = [
            X86Reg.RAX, X86Reg.RCX, X86Reg.RDX, X86Reg.RBX,
            X86Reg.RSP, X86Reg.RBP, X86Reg.RSI, X86Reg.RDI, X86Reg.RIP
        ]

        gen_regs_64 = [
            X86Reg.R9, X86Reg.R10, X86Reg.R11, X86Reg.R12,
            X86Reg.R13, X86Reg.R14, X86Reg.R15
        ]

        # TODO parse the entire buffer
        # regs = Registers()
        regs = self.ctx.vmi.get_vcpuregs(0)
        iter = struct.iter_unpack(pack_fmt, unhexlify(packet_data))
        for r in gen_regs_32:
            value, *rest = next(iter)
            logging.debug('%s: %x', r.name, value)
            regs[r] = value
        # 64 bits ?
        if addr_width == 8:
            for r in gen_regs_64:
                value, *rest = next(iter)
                logging.debug('%s: %x', r.name, value)
                regs[r] = value
        # eflags
        value, *rest = next(iter)
        logging.debug('%s: %x', X86Reg.RFLAGS.name, value)
        regs[X86Reg.RFLAGS] = value
        # TODO segment registers
        try:
            self.ctx.vmi.set_vcpuregs(regs, 0)
        except LibvmiError:
            return False
        else:
            self.send_packet(GDBPacket(b'OK'))
            return True

    def detach(self, packet_data):
        # detach
        self.attached = False
        try:
            self.ctx.vmi.resume_vm()
        except LibvmiError:
            pass
        self.send_packet(GDBPacket(b'OK'))
        return True

    def read_memory(self, packet_data):
        m = re.match(b'(?P<addr>.*),(?P<length>.*)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            length = int(m.group('length'), 16)
            # TODO partial read
            try:
                buffer, bytes_read = self.ctx.vmi.read_va(addr, self.ctx.target_pid, length)
            except LibvmiError:
                return False
            else:
                self.send_packet(GDBPacket(hexlify(buffer)))
                return True
        return False

    def write_memory(self, packet_data):
        m = re.match(b'(?P<addr>.+),(?P<length>.+):(?P<data>.+)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            length = int(m.group('length'), 16)
            data = unhexlify(m.group('data'))
            # TODO partial write
            try:
                bytes_written = self.ctx.vmi.write_va(addr, self.ctx.target_pid, data)
            except LibvmiError:
                return False
            else:
                self.send_packet(GDBPacket(b'OK'))
                return True
        return False

    def cont_execution(self, packet_data):
        # TODO resume execution at addr
        addr = None
        m = re.match(b'(?P<addr>.+)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            return False
        self.ctx.vmi.resume_vm()
        self.send_packet(GDBPacket(b'OK'))
        return True

    def singlestep(self, packet_data):
        # TODO resume execution at addr
        addr = None
        m = re.match(b'(?P<addr>.+)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            return False

        cb_data = {
            'interrupted': False
        }

        def cb_on_sstep(vmi, event):
            self.log.debug('singlestepping')
            vmi.pause_vm()
            cb_data['interrupted'] = True

        num_vcpus = self.ctx.vmi.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), cb_on_sstep)
        self.ctx.vmi.register_event(ss_event)

        self.ctx.vmi.resume_vm()
        while not cb_data['interrupted']:
            self.ctx.vmi.listen(1000)

        self.ctx.vmi.listen(0)
        self.ctx.vmi.clear_event(ss_event)
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

    def breakin(self, packet_data):
        self.ctx.attach()
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True
