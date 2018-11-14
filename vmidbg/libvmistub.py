import logging
import re
import struct
from binascii import hexlify

from libvmi import LibvmiError

from .gdbstub import GDBStub, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE


class LibVMIStub(GDBStub):

    def __init__(self, conn, addr, debug_ctx):
        super().__init__(conn, addr)
        self.ctx = debug_ctx
        self.cmd_to_handler = {
            GDBCmd.CMD_Q: self.cmd_q,
            GDBCmd.CMD_CAP_H: self.cmd_H,
            GDBCmd.CMD_QMARK: self.cmd_qmark,
            GDBCmd.CMD_G: self.read_registers,
            GDBCmd.CMD_CAP_D: self.cmd_D,
            GDBCmd.CMD_M: self.read_memory,
            GDBCmd.CMD_C: self.cont_execution
        }

    def cmd_q(self, packet_data):
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

    def cmd_H(self, packet_data):
        m = re.match(b'(?P<op>[cg])(?P<tid>([0-9a-f])+|-1)', packet_data)
        if m:
            op = m.group('op')
            tid = int(m.group('tid'), 16)
            self.cur_tid = tid
            # TODO op, Enn
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def cmd_qmark(self, packet_data):
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
            regs.x86.rax, regs.x86.rcx, regs.x86.rdx, regs.x86.rbx,
            regs.x86.rsp, regs.x86.rbp, regs.x86.rsi, regs.x86.rdi, regs.x86.rip
        ]

        gen_regs_64 = [
            regs.x86.r9, regs.x86.r10, regs.x86.r11, regs.x86.r12,
            regs.x86.r13, regs.x86.r14, regs.x86.r15
        ]
        # not available through libvmi
        seg_regs = [x+1 for x in range(0, 6)]
        # write general registers
        msg = b''.join([hexlify(struct.pack(pack_fmt, r)) for r in gen_regs_32])
        if addr_width == 8:
            msg += b''.join([hexlify(struct.pack(pack_fmt, r)) for r in gen_regs_64])
        # write eflags
        msg += hexlify(struct.pack(pack_fmt, regs.x86.rflags))
        # write segment registers
        msg += b''.join([hexlify(struct.pack(pack_fmt, r)) for r in seg_regs])
        self.send_packet(GDBPacket(msg))
        return True

    def cmd_D(self, packet_data):
        # detach
        self.attached = False
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
                buffer = b''
            self.send_packet(GDBPacket(hexlify(buffer)))
            return True
        return False

    def cont_execution(self, packet_data):
        addr = None
        m = re.match(b'(?P<addr>.+)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
        # TODO resume execution at addr
        self.ctx.vmi.resume_vm()
        return True
