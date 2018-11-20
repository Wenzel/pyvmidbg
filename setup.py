#!/usr/bin/env python3

import os
from setuptools import setup


def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        return f.read()


setup(
    name='vmidbg',
    version='0.1',
    description='LibVMI-based GDB server',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='Mathieu Tarral',
    author_email='mathieu.tarral@protonmail.com',
    url='https://github.com/Wenzel/pyvmidbg',
    setup_requires=[''],
    install_requires=['docopt', 'lxml', 'libvmi'],
    tests_require=["pytest", "pytest-pep8", "libvirt-python"],
    packages=['vmidbg'],
    entry_points={
        'console_scripts': ['vmidbg=vmidbg.main:main'],
    }
)
