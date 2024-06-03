'''
File: authentification copy.py
Project: L1
Created Date: Monday July 20th 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Monday, 20th July 2020 12:15:51 pm
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

# from __future__ import print_function
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB
# from unicorn.arm_const import UC_ARCH_ARM, UC_MODE_THUMB

from termcolor import colored, cprint

import binascii
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

import sys
import os

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


class PINEmulator:
    # memory address where emulation starts
    INST_ADDRESS    = 0x8000000
    RAM_ADDRESS     = 0x20000000
    IO_ADDRESS      = 0x10000000
    NVM_ADDRESS     = 0x50000000

    INPUT_ADD       = 0x10000000
    OUTPUT_ADD      = 0x10000010
    

    def __init__(self, target_app_folder_path):
        self.bin_path = target_app_folder + '/bin/pin.bin'
        self.elf_path = target_app_folder + '/bin/pin.elf'
        self.THUMB_CODE = load_code(self.bin_path)

    def execute(self, candidate_pin):
        global nvm_content
        try:
            # Initialize emulator in thumb mode
            mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

            # map 128kiB of flash memory for the code
            mu.mem_map(self.INST_ADDRESS, 128 * 1024)
            # map 8kiB of ram memory
            mu.mem_map(self.RAM_ADDRESS, 8 * 1024)
            # map 1kiB for Non Volatile Memory (NVM)
            mu.mem_map(self.NVM_ADDRESS, 1 * 1024)
            # map 1kiB for IO buffer
            mu.mem_map(self.IO_ADDRESS, 1 * 1024)

            # write machine code to flash
            mu.mem_write(self.INST_ADDRESS, self.THUMB_CODE)

            #write nvm content
            mu.mem_write(self.NVM_ADDRESS, nvm_content)

            #write the candidate PIN in io buffer
            mu.mem_write(self.INPUT_ADD, candidate_pin)


            # emulate machine code until timeout
            # Note we start at INST_ADDRESS | 1 to indicate THUMB mode.
            # mu.emu_start( start_address, end_address, timeout, nb_steps)
            mu.emu_start(self.INST_ADDRESS | 1, extract_symbol_address("_exit", self.elf_path), 1000000, 100000)

            nvm_content = bytes(mu.mem_read(self.NVM_ADDRESS, 1024))
            tries_left = nvm_content[0]

            verif_result = mu.mem_read(self.OUTPUT_ADD, 1)[0]
            
            # if verif_result == 255:
            #     cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow')
            # elif verif_result == 1:
            #     cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
            # elif verif_result == 2:
            #     cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
            # else:
            #     print("Résultat inattendu: %i" %verif_result)

            return (verif_result, tries_left)

        except UcError as e:
            print("ERROR: %s" % e)

def test_all_pin(target_app_folder):
    em = PINEmulator(target_app_folder)
    for b1 in range(10):
        for b2 in range(10):
            for b3 in range(10):
                for b4 in range(10):
                    pin_candidate = bytes([b1, b2, b3, b4])
                    print("Testing %i%i%i%i:" %(b1, b2, b3, b4), end=' ')
                    
                    (verif_result, tries_left) = em.execute(pin_candidate)

                    if verif_result == 255:
                        cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow')
                    elif verif_result == 1:
                        cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
                    elif verif_result == 2:
                        cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
                    else:
                        print("Résultat inattendu: %i" %verif_result)

                    if verif_result != 255:
                        return True
    return False

if __name__ == '__main__':

    target_app_folder = '.'
    if len(sys.argv) > 1:
        target_app_folder = sys.argv[1]

    target_app_folder = os.path.abspath(target_app_folder)
    attack_success = test_all_pin(target_app_folder)
    if attack_success:
        sys.exit(1)
    else:
        sys.exit(0)


    