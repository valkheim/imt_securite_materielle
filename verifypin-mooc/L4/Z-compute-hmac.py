'''
File: A-authentification.py
Project: L4
Created Date: Monday August 24th 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Tuesday, 25th August 2020 8:43:47 am
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

# from __future__ import print_function
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *

from termcolor import colored, cprint

import binascii
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

import sys
import os
import hmac

# we read the elf file to automatically extract the address and size of the given symbol
def extract_symbol_range(symbol_name, elf_path):
    e = ELFFile(open(elf_path, 'rb'))
    symbol_tables = [s for s in e.iter_sections() if isinstance(s, SymbolTableSection)]
    for section in symbol_tables:
        for symbol in section.iter_symbols():
            if symbol.name == symbol_name:
                return range(symbol['st_value'], symbol['st_size'] + symbol['st_value'])

def extract_symbol_address(symbol_name, elf_path):
    return extract_symbol_range(symbol_name, elf_path).start


def parse_input_pin(input_pin_str):
        ascii_array = binascii.a2b_qp(input_pin_str)
        return bytes([elem - 0x30 for elem in ascii_array])

def display_pin(input_pin):
    return bytes([elem + 0x30 for elem in input_pin]).decode("utf-8") 

# code to be emulated
def load_code(path):
    return open(path, 'rb').read()

def init_nvm(nb_essais):
    content = bytearray([0 for _ in range(1024)])
    content[0] = nb_essais
    return bytes(content)

nvm_content = init_nvm(3)




if __name__ == '__main__':
    print("> Veuillez entrer votre clé secrète: ", end="")
    secret_key = input()
    print("> Veuillez entrer votre PIN: ", end="")
    input_pin = input() # input as string
    candidate_pin = parse_input_pin(input_pin) # input as bytes
    h = hmac.new(bytes(secret_key, "ascii"), digestmod='sha256')
    h.update(bytearray(candidate_pin))
    hash = h.digest()

    hash_str = "{ "

    for b in hash:
        hash_str += "0x%x, " %b

    
    hash_str = hash_str[:-2]
    hash_str += " }"

    print(hash_str)
