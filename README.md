pycave
======

Simple tool to find code caves in Portable Executable (PE) files.

## Description

This tool is inspired by [Cminer](https://github.com/EgeBalci/Cminer) and aims to find code caves in PE files.

## Requirements

This tool requires the [pefile](https://github.com/erocarrera/pefile/).

```bash
$ pip3 install -r requirements.txt
```

**OR**

```bash
$ pip3 install pefile
```

## Install

Checkout the source: `git clone xx`

## Getting Started

```bash
usage: pycave.py [-h] -f FILE_NAME [-s SIZE] [-b BASE]

Find code caves in PE files

optional arguments:
  -h, --help            show this help message and exit
  -f FILE_NAME, --file FILE_NAME
                        PE file
  -s SIZE, --size SIZE  Min. cave size
  -b BASE, --base BASE  Image base

$ python pycave.py -f putty.exe -s 200
[+] Minimum code cave size: 200
[+] Image Base:  0x00400000
[+] Loading "putty.exe"...

[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.

[+] Looking for code caves...
[+] Code cave found in .rdata           Size: 343 bytes         RA: 0x00000D71  VA: 0x00402771
[+] Code cave found in .rdata           Size: 260 bytes         RA: 0x000219B4  VA: 0x004233B4
[+] Code cave found in .rdata           Size: 257 bytes         RA: 0x00021BB7  VA: 0x004235B7
[+] Code cave found in .data            Size: 205 bytes         RA: 0x000252CC  VA: 0x0042B4CC
[+] Code cave found in .data            Size: 223 bytes         RA: 0x000253D3  VA: 0x0042B5D3
```

## License

This project is released under the Apache 2 license. See LICENCE file.