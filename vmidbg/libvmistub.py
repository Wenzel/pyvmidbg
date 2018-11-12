import logging
import re
import struct
from binascii import hexlify

from .gdbstub import GDBStub, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE


class LibVMIStub(GDBStub):

    def __init__(self, conn, addr):
        super().__init__(conn, addr)
        self.cmd_to_handler = {
            GDBCmd.CMD_Q: self.cmd_q,
            GDBCmd.CMD_CAP_H: self.cmd_H,
            GDBCmd.CMD_QMARK: self.cmd_qmark,
            GDBCmd.CMD_G: self.cmd_g,
            GDBCmd.CMD_CAP_D: self.cmd_D,
            GDBCmd.CMD_M: self.cmd_m
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

    def cmd_g(self, packet_data):
        # test data, 15 registers, 32 bits
        # eax -> edi (8 regs)
        registers = [x+1 for x in range(1, 9)]
        # eip, eflags (2 regs)
        registers.extend([x+1 for x in range(9, 11)])
        # ss -> gs (6 regs)
        registers.extend([x+1 for x in range(11, 17)])
        msg = b''
        for r in registers:
            msg += hexlify(struct.pack('@I', r))
        self.send_packet(GDBPacket(msg))
        return True

    def cmd_D(self, packet_data):
        # detach
        self.attached = False
        self.send_packet(GDBPacket(b'OK'))
        return True

    def cmd_m(self, packet_data):
        m = re.match(b'(?P<addr>.*),(?P<length>.*)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            length = int(m.group('length'), 16)
            msg = b'%.2x' * 0 * length
            self.send_packet(GDBPacket(msg))
            return True
        return False