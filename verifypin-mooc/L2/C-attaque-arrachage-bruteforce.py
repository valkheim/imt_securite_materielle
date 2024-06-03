'''
File: machine.py
Project: Enonce
Created Date: Tuesday June 2nd 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Tuesday, 21st July 2020 1:48:45 pm
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *

import sys
import os
from termcolor import colored, cprint

import binascii
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

# code to be emulated
def load_code(path):
    return open(path, 'rb').read()

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

def init_nvm(nb_essais):
    content = bytearray([0 for _ in range(1024)])
    content[0] = nb_essais
    cprint('Vous avez %i essais pour valider le PIN.' %nb_essais)
    return bytes(content)

nvm_content = init_nvm(3)

class PINEmulator:
    # memory addresses
    INST_ADDRESS    = 0x8000000
    RAM_ADDRESS     = 0x20000000
    IO_ADDRESS      = 0x10000000
    NVM_ADDRESS     = 0x50000000

    INPUT_ADD       = 0x10000000
    OUTPUT_ADD      = 0x10000010

    timer = 0

    def __init__(self, target_app_folder_path):
        self.bin_path = target_app_folder + '/bin/pin.bin'
        self.elf_path = target_app_folder + '/bin/pin.elf'
        self.THUMB_CODE = load_code(self.bin_path)

    # def hook_ca_time(self, uc, address, size, user_data):
    #     if self.ca_range.start <= address < self.ca_range.stop:
    #         self.timer += 1

    def try_candidate(self, candidate_pin):
        self.timer = 0
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

            # self.ca_range = extract_symbol_range('compare_arrays', self.elf_path)
            # tracing instructions to measure time in verify_pin function
            # mu.hook_add(UC_HOOK_CODE, self.hook_ca_time)

            #write the candidate PIN in io buffer
            mu.mem_write(self.INPUT_ADD, candidate_pin)

            # emulate machine code until timeout
            # Note we start at INST_ADDRESS | 1 to indicate THUMB mode.
            # mu.emu_start( start_address, end_address, timeout, nb_steps)
            mu.emu_start(self.INST_ADDRESS | 1, extract_symbol_address("arrache", self.elf_path), 1000000, 10000)

            nvm_content = bytes(mu.mem_read(self.NVM_ADDRESS, 1024))
            tries_left = nvm_content[0]

            verif_result = mu.mem_read(self.OUTPUT_ADD, 1)[0]
            
            # if verif_result == 255:
            #     cprint("! PIN incorrect ! Essais restant: %i. Comparaison de tableaux réalisée en %i instructions." %(tries_left, self.timer), 'yellow')
            # elif verif_result == 1:
            #     cprint("*** PIN accepté ***", 'green')
            # elif verif_result == 2:
            #     cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
            # else:
            #     print("Résultat inattendu: %i.  Essais restant: %i. Comparaison de tableaux réalisée en %i instructions." %(verif_result, tries_left, self.timer))

            return (verif_result, tries_left)

        except UcError as e:
            print("ERROR: %s" % e)

def test_all_pin(target_app_folder):
    em = PINEmulator(target_app_folder)
    verif_result = 255
    for b1 in range(10):
        for b2 in range(10):
            for b3 in range(10):
                for b4 in range(10):
                    pin_candidate = bytes([b1, b2, b3, b4])
                    print("Testing %i%i%i%i:" %(b1, b2, b3, b4), end=' ')
                    
                    (verif_result, tries_left) = em.try_candidate(pin_candidate)

                    if verif_result == 255:
                        cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow')
                    elif verif_result == 1:
                        cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
                    elif verif_result == 2:
                        cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
                    else:
                        print("Résultat inattendu: %i. Essais restant: %i." %(verif_result, tries_left))

                    if verif_result == 1 or verif_result == 2:
                        return verif_result
    return verif_result  
        

if __name__ == '__main__':
    target_app_folder = '.'
    if len(sys.argv) > 1:
        target_app_folder = sys.argv[1]

    target_app_folder = os.path.abspath(target_app_folder)

    attack_result = test_all_pin(target_app_folder)

    if attack_result == 1:
        sys.exit(1)
    else:
        sys.exit(0)
    
