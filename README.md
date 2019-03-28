# pyvmidbg

[![Slack](https://maxcdn.icons8.com/Color/PNG/48/Mobile/slack-48.png)](https://vmidbg.slack.com)
[![Join the chat at https://gitter.im/pyvmidbg/Lobby](https://badges.gitter.im/trailofbits/algo.svg)](https://gitter.im/pyvmidbg/Lobby)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)


> LibVMI-based GDB server, implemented in Python

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Demo](#demo)
- [References](#references)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Overview

This GDB stub allows you to debug a remote process running in a VM with
your favorite GDB frontend.

By leveraging *virtual machine introspection*, the stub remains **stealth** and requires 
**no modification** of the guest.

### Why debugging from the hypervisor ?

Operating systems debug API's are problematic:

1. they have never been designed to deal with malwares, and lack the stealth and robustness required when 
analyzing malicious code
2. they have an observer effect, by implicitly modifying the process environment being debugged
3. this observer effect might be intentional to protect OS features (`Windows PatchGuard`/`Protected Media Path` are disabled)
4. modern OS have a high degree of kernel security mechanisms that narrows the debugger's view of the system
 (`Windows 10 Virtual Secure Mode`)
5. debugging low-level processes and kernel functions interacting directly with the transport protocol used by the debug agent can
    turn into a infinite recursion hell (eg. debugging TCP connections and having a kernel debug stub communicating via TCP)
5. in special cases the "Operating System" lacks debugging capabilities (`unikernels`)

Existing solutions like GDB stubs included in `QEMU`, `VMware` or `VirtualBox` can only
pause the VM and debug the kernel, but lack the guest knowledge to track and follow the rest of the processes.

### Vision

![vmidbg](https://user-images.githubusercontent.com/964610/53703373-9fed3580-3e11-11e9-96f8-47b3f38044cf.jpg)

## Features

- intercept process at `CR3` load
- read/write memory
- get/set registers
- continue execution
- singlestep
- breakin (`CTRL-C`)
- insert/remove software breakpoint

## Requirements

- `Python >= 3.4`
- `python3-docopt`
- `python3-lxml`
- [`python3-libvmi`](https://github.com/libvmi/python)
- `Xen`

## Install

~~~
virtualenv -p python3 venv
source venv/bin/activate
pip install .
~~~

Note: If you don't want to install `Xen`, [vagrant-xen-pyvmidbg](https://github.com/Wenzel/vagrant-xen-pyvmidbg)
provides a Vagrant environment based on `KVM`, with ready to use `Windows` and `Linux` VMs.

## Usage

~~~
vmidbg <port> <vm> [<process>]
~~~

## Demo

[high-quality](https://drive.google.com/open?id=1clumU_P8K-M1mgQ4RaNVSrWg6sxojw8d)

1. starts `cmd.exe` in `Windows XP` nested VM in Xen
2. starts `pyvmidbg` and target a process named `cmd`
3. connects to stub with `radare2`
4. set breakpoints on `ntdll!NtOpenFile` and `ntkrnlpa!NtOpenFile`
5. avoid breakpoints from the rest of the system, only hit if `cmd.exe` is executing

![pyvmidbg](https://github.com/Wenzel/wenzel.github.io/blob/master/public/images/pyvmidbg-demo.gif)

## References

- [vmidbg](https://github.com/Zentific/vmidbg): original idea and C implementation
- [plutonium-dbg](https://github.com/plutonium-dbg/plutonium-dbg): [GDB server protocol parsing](https://github.com/plutonium-dbg/plutonium-dbg/blob/master/clients/gdbserver.py)
- [ollydbg2-python](https://github.com/0vercl0k/ollydbg2-python): [GDB server protocol parsing](https://github.com/0vercl0k/ollydbg2-python/blob/master/samples/gdbserver/gdbserver.py)
- [GDB RSP protocol specifications](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html)

## Maintainers

[@Wenzel](https://github.com/Wenzel)

## Contributing

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[GNU General Public License v3.0](https://github.com/Wenzel/pyvmidbg/blob/master/LICENSE)
