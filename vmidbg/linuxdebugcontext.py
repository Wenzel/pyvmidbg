import logging
import re

from libvmi import AccessContext, TranslateMechanism


class LinuxThread:

    def __init__(self, id):
        self.id = id

    def is_alive(self):
        return True


class LinuxTaskDescriptor:

    def __init__(self, desc_addr, vmi):
        self.vmi = vmi
        self.addr = desc_addr
        self.dtb = self.vmi.read_32_va(self.addr + self.vmi.get_offset('linux_pgd'), 0)
        self.name = self.vmi.read_str_va(self.addr + self.vmi.get_offset('linux_name'), 0)
        self.pid = self.vmi.read_32_va(self.addr + self.vmi.get_offset('linux_pid'), 0)
        self.mm = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('linux_mm'), 0)
        task_addr = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('linux_tasks'), 0)
        self.next_desc = task_addr - self.vmi.get_offset('linux_tasks')

    def __str__(self):
        return "[{}] {} @{}".format(self.pid, self.name, hex(self.addr))


class LinuxDebugContext:

    def __init__(self, vmi, process):
        self.vmi = vmi
        self.target_name = process
        self.target_desc = None
        self.threads = [LinuxThread(1)]
        # misc: print kernel base address
        logging.info('kernel base: @%s', hex(self.vmi.translate_ksym2v('start_kernel')))

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
            logging.warning('Found multiple processes matching %s, picking the first match', self.target_name)
        self.target_desc = found[0]
        # 3 - check if kernel thread (not supported)
        if self.target_desc.mm == 0:
            raise RuntimeError('intercepting kernel threads is not supported')
        # 4 - wait for our process to be scheduled
        # TODO

    def detach(self):
        self.vmi.resume_vm()

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_PID,
                             addr=address, pid=self.target_desc.pid)

    def get_dtb(self):
        return self.target_desc.dtb

    def list_processes(self):
        head_desc = self.vmi.translate_ksym2v('init_task')
        desc_addr = head_desc
        while True:
            desc = LinuxTaskDescriptor(desc_addr, self.vmi)
            yield desc
            # read next address
            desc_addr = desc.next_desc
            if desc_addr == head_desc:
                break

    def list_threads(self):
        return self.threads

    def get_current_thread(self):
        return self.threads[0]
