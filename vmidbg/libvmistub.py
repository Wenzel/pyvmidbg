import logging
import re
import struct
import threading
from functools import lru_cache
from lxml import etree
from binascii import hexlify, unhexlify
from concurrent.futures import ThreadPoolExecutor

from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS, VMIOS, LibvmiError, X86Reg
from libvmi.event import EventResponse, SingleStepEvent, IntEvent

from .gdbstub import GDBStub, GDBPacket, GDBCmd, GDBSignal, PACKET_SIZE
from .rawdebugcontext import RawDebugContext
from .linuxdebugcontext import LinuxDebugContext
from .windowsdebugcontext import WindowsDebugContext

SW_BREAKPOINT = b'\xcc'


class LibVMIStub(GDBStub):

    def __init__(self, conn, addr, vm_name, process):
        super().__init__(conn, addr)
        self.vm_name = vm_name
        self.process = process
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
            GDBCmd.WRITE_DATA_MEMORY: self.write_data_memory,
            GDBCmd.CONTINUE: self.cont_execution,
            GDBCmd.SINGLESTEP: self.singlestep,
            GDBCmd.IS_THREAD_ALIVE: self.is_thread_alive,
            GDBCmd.REMOVE_XPOINT: self.remove_xpoint,
            GDBCmd.INSERT_XPOINT: self.insert_xpoint,
            GDBCmd.BREAKIN: self.breakin,
            GDBCmd.V_FEATURES: self.v_features,
        }
        self.features = {
            b'multiprocess': False,
            b'swbreak': True,
            b'hwbreak': False,
            b'qRelocInsn': False,
            b'fork-events': False,
            b'vfork-events': False,
            b'exec-events': False,
            b'vContSupported': True,
            b'QThreadEvents': False,
            b'QStartNoAckMode': True,
            b'no-resumed': False,
            b'xmlRegisters': False,
            b'qXfer:memory-map:read': True
        }
        # [addr] -> [saved_opcode]
        self.addr_to_op = {}
        self.stop_listen = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=1)
        # store the last addr where a swbreakpoint was hit
        # but it was not our targeted process
        # used in cb_on_sstep_recoil to restore the breakpoint after
        # the recoil
        self.last_addr_wrong_swbreak = None

    def __enter__(self):
        # init LibVMI
        self.vmi = Libvmi(self.vm_name, init_flags=INIT_DOMAINNAME | INIT_EVENTS, partial=True)
        self.vmi.init_paging(flags=0)
        # catch every exception to force a clean exit with __exit__
        # where vmi.destroy() must be called
        try:
            # determine debug context
            if not self.process:
                self.ctx = RawDebugContext(self.vmi)
            else:
                self.vmi.init_os()
                ostype = self.vmi.get_ostype()
                if ostype == VMIOS.WINDOWS:
                    self.ctx = WindowsDebugContext(self.vmi, self.process)
                elif ostype == VMIOS.LINUX:
                    self.ctx = LinuxDebugContext(self.vmi, self.process)
                else:
                    raise RuntimeError('unhandled ostype: {}'.format(ostype.value))
            # register some events
            # register interrupt event
            self.int_event = IntEvent(self.cb_on_int3)
            self.vmi.register_event(self.int_event)
            # single step event to handle wrong hits by sw breakpoints
            # enabled via EventResponse.TOGGLE_SINGLESTEP
            num_vcpus = self.vmi.get_num_vcpus()
            self.ss_event_recoil = SingleStepEvent(range(num_vcpus), self.cb_on_sstep_recoil, enable=False)
            self.vmi.register_event(self.ss_event_recoil)
            self.ctx.attach()
            self.attached = True
        except:
            logging.exception('Exception while initializing debug context')
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.ctx.detach()
            self.attached = False
        except:
            logging.exception('Exception while detaching from debug context')
        finally:
            self.vmi.destroy()
        # TODO restore opcodes

    @lru_cache(maxsize=None)
    def get_memory_map_xml(self):
        # retrieve list of maps
        root = etree.Element('memory-map')
        for page_info in self.vmi.get_va_pages(self.ctx.get_dtb()):
            # <memory type="ram" start="addr" length="length"/>
            addr = str(hex(page_info.vaddr))
            size = str(hex(page_info.size))
            region = etree.Element('memory', type='ram', start=addr, length=size)
            root.append(region)
        doctype = '<!DOCTYPE memory-map ' \
                  'PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN"' \
                  ' "http://sourceware.org/gdb/gdb-memory-map.dtd">'
        xml = etree.tostring(root, xml_declaration=True, doctype=doctype, encoding='UTF-8')
        return xml

# commands
    def gen_query_get(self, packet_data):
        if re.match(b'Supported', packet_data):
            reply = self.set_supported_features(packet_data)
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
            reply = b'm'
            for thread in self.ctx.list_threads():
                if reply != b'm':
                    reply += b','
                reply += b'%x' % thread.id
            self.send_packet(GDBPacket(reply))
            return True
        if re.match(b'sThreadInfo', packet_data):
            # send end of thread list
            self.send_packet(GDBPacket(b'l'))
            return True
        m = re.match(b'ThreadExtraInfo,(?P<thread_id>.+)', packet_data)
        if m:
            tid = int(m.group('thread_id'), 16)
            thread = self.ctx.get_thread(tid)
            if not thread:
                return False
            self.send_packet(GDBPacket(thread.name.encode()))
            return True
        if re.match(b'Attached', packet_data):
            # attach existing process: 0
            # attach new process: 1
            self.send_packet(GDBPacket(b'0'))
            return True
        if re.match(b'C', packet_data):
            # return current thread id
            self.send_packet(GDBPacket(b'QC%x' % self.ctx.cur_tid))
            return True
        m = re.match(b'Xfer:memory-map:read::(?P<offset>.*),(?P<length>.*)', packet_data)
        if m:
            offset = int(m.group('offset'), 16)
            length = int(m.group('length'), 16)
            xml = self.get_memory_map_xml()
            chunk = xml[offset:offset+length]
            msg = b'm%s' % chunk
            if len(chunk) < length or offset+length >= len(xml):
                # last chunk
                msg = b'l%s' % chunk
            self.send_packet(GDBPacket(msg))
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
            self.log.debug('Current thread: %s', tid)
            self.ctx.cur_tid = tid
            # TODO op, Enn
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def target_status(self, packet_data):
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

    def read_registers(self, packet_data):
        addr_width = self.vmi.get_address_width()
        if addr_width == 4:
            pack_fmt = '@I'
        else:
            pack_fmt = '@Q'

        cur_thread = self.ctx.get_thread()
        regs = cur_thread.read_registers()

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
        addr_width = self.vmi.get_address_width()
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
        regs = self.vmi.get_vcpuregs(0)
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
            self.vmi.set_vcpuregs(regs, 0)
        except LibvmiError:
            return False
        else:
            self.send_packet(GDBPacket(b'OK'))
            return True

    def detach(self, packet_data):
        # detach
        self.attached = False
        try:
            self.vmi.resume_vm()
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
                buffer, bytes_read = self.vmi.read(self.ctx.get_access_context(addr), length)
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
                bytes_written = self.vmi.write(self.ctx.get_access_context(addr), data)
            except LibvmiError:
                return False
            else:
                self.send_packet(GDBPacket(b'OK'))
                return True
        return False

    def write_data_memory(self, packet_data):
        # ‘X addr,length:XX…’
        m = re.match(b'(?P<addr>.+),(?P<length>.+):(?P<data>.*)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            length = int(m.group('length'), 16)
            data = m.group('data')
            # TODO partial write
            try:
                bytes_written = self.vmi.write(self.ctx.get_access_context(addr), data)
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
        self.action_continue()
        self.send_packet(GDBPacket(b'OK'))
        # TODO race condition if listen thread started by action_continue
        # sends a packet before our 'OK' reply
        return True

    def singlestep(self, packet_data):
        # TODO resume execution at addr
        addr = None
        m = re.match(b'(?P<addr>.+)', packet_data)
        if m:
            addr = int(m.group('addr'), 16)
            return False

        self.action_singlestep()

        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

    def is_thread_alive(self, packet_data):
        m = re.match(b'(?P<tid>.+)', packet_data)
        if m:
            tid = int(m.group('tid'), 16)
            thread = self.ctx.get_thread(tid)
            if not thread:
                # TODO Err XX
                return False
            reply = None
            if thread.is_alive():
                reply = b'OK'
            else:
                # TODO thread is dead
                reply = b'EXX'
            self.send_packet(GDBPacket(reply))
            return True
        return False

    def remove_xpoint(self, packet_data):
        # ‘z type,addr,kind’
        m = re.match(b'(?P<type>[0-9]),(?P<addr>.+),(?P<kind>.+)', packet_data)
        if not m:
            return False
        btype = int(m.group('type'))
        addr = int(m.group('addr'), 16)
        # kind -> size of breakpoint
        kind = int(m.group('kind'), 16)
        if btype == 0:
            # software breakpoint
            # already removed ?
            if addr in self.addr_to_op.keys():
                self.toggle_swbreak(addr, False)
                self.addr_to_op.pop(addr)
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def insert_xpoint(self, packet_data):
        # ‘Z type,addr,kind’
        m = re.match(b'(?P<type>[0-9]),(?P<addr>.+),(?P<kind>.+)', packet_data)
        if not m:
            return False
        btype = int(m.group('type'))
        addr = int(m.group('addr'), 16)
        # kind -> size of breakpoint
        kind = int(m.group('kind'), 16)
        if btype == 0:
            # software breakpoint
            # read old opcode
            try:
                buffer, bytes_read = self.vmi.read(self.ctx.get_access_context(addr), kind)
            except LibvmiError:
                return False
            if bytes_read < kind:
                # read error
                return False
            self.addr_to_op[addr] = buffer
            # write breakpoint
            try:
                self.toggle_swbreak(addr, True)
            except LibvmiError:
                # write error
                self.addr_to_op.pop(addr)
                return False
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

    def breakin(self, packet_data):
        # stop event thread
        self.stop_listen.set()
        self.ctx.attach()
        msg = b'S%.2x' % GDBSignal.TRAP.value
        self.send_packet(GDBPacket(msg))
        return True

# callbacks
    def cb_on_sstep_recoil(self, vmi, event):
        self.log.debug('cb_on_sstep')
        # restore software breakpoint
        self.toggle_swbreak(self.last_addr_wrong_swbreak, True)
        self.last_addr_wrong_swbreak = None
        # done singlestepping
        return EventResponse.TOGGLE_SINGLESTEP

    def cb_on_int3(self, vmi, event):
        self.log.debug('cb_on_int3')
        # invalidate libvmi caches
        self.vmi.v2pcache_flush()
        self.vmi.pidcache_flush()
        self.vmi.rvacache_flush()
        self.vmi.symcache_flush()
        # set default reinject behavior
        event.reinject = 0
        addr = event.cffi_event.x86_regs.rip
        if addr not in self.addr_to_op.keys():
            # not our breakpoint, reinject
            event.reinject = 1
            self.log.debug('reinject')
            return EventResponse.NONE
        if not self.process:
            # not target
            self.log.debug('hit !')
            # pause
            self.vmi.pause_vm()
            self.stop_listen.set()
            # report swbreak stop to client
            self.send_packet_noack(GDBPacket(b'T%.2xswbreak:;' % GDBSignal.TRAP.value))
        else:
            # check if it's our targeted process
            dtb = event.cffi_event.x86_regs.cr3
            if dtb != self.ctx.get_dtb():
                desc = self.ctx.dtb_to_desc(dtb)
                self.log.debug('wrong process: %s', desc.name)
                # store current address to restore breakpoint in cb_sstep_recoil
                self.last_addr_wrong_swbreak = addr
                # restore original opcode
                self.toggle_swbreak(addr, False)
                # prepare to singlestep
                return EventResponse.TOGGLE_SINGLESTEP
            else:
                self.log.debug('hit !')
                # pause
                self.vmi.pause_vm()
                self.stop_listen.set()
                thread = self.ctx.get_current_running_thread()
                if not thread:
                    tid = -1
                else:
                    tid = thread.id
                # report swbreak stop to client
                self.send_packet_noack(GDBPacket(b'T%.2xswbreak:;thread:%x;' %
                    (GDBSignal.TRAP.value, tid)))

    def v_features(self, packet_data):
        if re.match(b'MustReplyEmpty', packet_data):
            # reply empty string
            # TODO refactoring, this should be treated as an unknown packet
            self.send_packet(GDBPacket(b''))
            return True
        if re.match(b'Cont\?', packet_data):
            # query the list of supported actions for vCont
            # reply: vCont[;action…]
            # we do not support continue or singlestep with a signal
            # but we have to advertise this to GDB, otherwise it won't use vCont
            self.send_packet(GDBPacket(b'vCont;c;C;s;S'))
            return True
        m = re.match(b'Cont(;(?P<action>[sc])(:(?P<tid>.*?))?).*', packet_data)
        if m:
            # vCont[;action[:thread-id]]…
            # we don't support threads
            action = m.group('action')
            if action == b's':
                self.action_singlestep()
                self.send_packet_noack(GDBPacket(b'T%.2x' % GDBSignal.TRAP.value))
                return True
            if action == b'c':
                self.action_continue()
                return True
        if re.match(b'Kill;(?P<pid>[a-fA-F0-9]).+', packet_data):
            # vKill;pid
            # ignore pid, and don't kill the process anyway
            # just detach from the target
            # sent when GDB client has a ^D
            self.attached = False
            self.send_packet(GDBPacket(b'OK'))
            return True
        return False

# helpers
    def action_singlestep(self):
        cb_data = {
            'interrupted': False
        }

        def cb_on_sstep(vmi, event):
            self.log.debug('singlestepping')
            vmi.pause_vm()
            cb_data['interrupted'] = True
        # unregister sstep_recoil
        self.vmi.clear_event(self.ss_event_recoil)

        num_vcpus = self.vmi.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), cb_on_sstep)
        self.vmi.register_event(ss_event)

        self.vmi.resume_vm()
        while not cb_data['interrupted']:
            self.vmi.listen(1000)

        self.vmi.listen(0)
        self.vmi.clear_event(ss_event)

        # reregister sstep_recoil
        self.vmi.register_event(self.ss_event_recoil)

    def action_continue(self):
        self.vmi.resume_vm()
        # start listening on VMI events
        self.stop_listen.clear()
        self.pool.submit(self.listen_events)

    def set_supported_features(self, packet_data):
        # split string and get features in a list
        # trash 'Supported
        req_features = re.split(b'[:|;]', packet_data)[1:]
        for f in req_features:
            if f[-1:] in [b'+', b'-']:
                name = f[:-1]
                value = True if f[-1:] == b'+' else False
            else:
                groups = f.split(b'=')
                name = groups[0]
                value = groups[1]
            # TODO check supported features
        reply_msg = b'PacketSize=%x' % PACKET_SIZE
        for name, value in self.features.items():
            if isinstance(value, bool):
                reply_msg += b';%s%s' % (name, b'+' if value else b'-')
            else:
                reply_msg += b';%s=%s' % (name, value)
        return reply_msg

    def listen_events(self):
        while not self.stop_listen.is_set():
            self.vmi.listen(2000)

    def toggle_swbreak(self, addr, set):
        if set:
            buffer = SW_BREAKPOINT
        else:
            buffer = self.addr_to_op[addr]
        bytes_written = self.vmi.write(self.ctx.get_access_context(addr), buffer)
        if bytes_written < len(buffer):
            raise LibvmiError
