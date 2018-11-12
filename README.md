# pyvmidbg

LibVMI-based GDB server, implemented in Python

![vmidbg](https://user-images.githubusercontent.com/964610/48309807-87ff5680-e581-11e8-8b4c-556462d09f60.png)

# Requirements

- `Python 3`
- `docopt`

# Setup

~~~
virtualenv -p python3 venv
source venv/bin/activate
pip install .
~~~

# Run

~~~
vmidbg <port>
~~~

example:
~~~
(venv) $ vmidbg 5000
INFO:server:listening on 127.0.0.1:5000
...
~~~

# References

- [vmidbg](https://github.com/Zentific/vmidbg): original idea and C implementation
- [plutonium-dbg](https://github.com/plutonium-dbg/plutonium-dbg): [GDB server protocol parsing](https://github.com/plutonium-dbg/plutonium-dbg/blob/master/clients/gdbserver.py)
- [ollydbg2-python](https://github.com/0vercl0k/ollydbg2-python): [GDB server protocol parsing](https://github.com/0vercl0k/ollydbg2-python/blob/master/samples/gdbserver/gdbserver.py)
- [GDB RSP protocol specifications](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html)
