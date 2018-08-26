# RISC-V for IDA
RISC-V ISA processor module for IDA 7.x written in Python.

## Overview
**riscv-ida** is just a simple RISC-V processor module for IDA, written in Python for best compatibility across platforms and to ease the development process.
Albeit very simple in nature, the plugin is already quite useful, allowing for instruction simplification, basic emulation and cross-references.

The main reason I decided to write a RISC-V module for IDA is that I'm working on a RISC-V emulator/virtual-machine project, and since I'm new to RISC-V, the best way to start is writing a disassembler, to get a feeling of the architecture.


## Install
Just copy riscv.py into *procs* folder of IDA. Start ida.exe and not ida64.exe, 64bit support is still missing (coming soon).

## Use
You need to manually choose RISC-V in the cpu selector when you load a binary. ELF loader support coming soon...

## Missing
Too much... :D

Soon to come:
- 64bit support in IDA
- Data cross reference
- Better emu
- Better integration with ELF loader (no more Unrecognized cpu blabla)

Someday:
- Stack tracing (very nice to have...)
- 128bit?

# License
GPLv3
