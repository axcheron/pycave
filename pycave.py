#!/usr/bin/python3

""" pycave.py: Dirty code to find code caves in Portable Executable files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.1'

import argparse
import pefile
import sys


def pycave(file_name, cave_size, base):

    image_base = int(base, 16)
    min_cave = cave_size
    fname = file_name
    pe = None

    try:
        pe = pefile.PE(fname)
    except IOError as e:
        print(e)
        sys.exit(0)
    except pefile.PEFormatError as e:
        print("[-] %s" % e.args[0])
        sys.exit(0)

    print("[+] Minimum code cave size: %d" % min_cave)
    print("[+] Image Base:  0x%08X" % image_base)
    print("[+] Loading \"%s\"..." % fname)

    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    if is_aslr:
        print("\n[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.")

    fd = open(fname, "rb")

    print("\n[+] Looking for code caves...")
    for section in pe.sections:
        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            fd.seek(section.PointerToRawData, 0)
            data = fd.read(section.SizeOfRawData)

            for byte in data:
                pos += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > min_cave:
                        raw_addr = section.PointerToRawData + pos - count - 1
                        vir_addr = image_base + section.VirtualAddress + pos - count - 1

                        print("[+] Code cave found in %s \tSize: %d bytes \tRA: 0x%08X \tVA: 0x%08X"
                              % (section.Name.decode(), count, raw_addr, vir_addr))
                    count = 0

    pe.close()
    fd.close()

if __name__ == "__main__":
    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description="Find code caves in PE files")

    # Add arguments
    parser.add_argument("-f", "--file", dest="file_name", action="store", required=True,
                        help="PE file", type=str)

    parser.add_argument("-s", "--size", dest="size", action="store", default=300,
                        help="Min. cave size", type=int)

    parser.add_argument("-b", "--base", dest="base", action="store", default="0x00400000",
                        help="Image base", type=str)

    args = parser.parse_args()

    if args.file_name:
        pycave(args.file_name, args.size, args.base)
    elif args.size:
        pycave(args.file_name, args.size, args.base)
    elif args.base:
        pycave(args.file_name, args.size, args.base)
    else:
        parser.print_help()
        exit(-1)
