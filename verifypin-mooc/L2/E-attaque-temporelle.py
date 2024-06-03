'''
File: machine.py
Project: Enonce
Created Date: Tuesday June 2nd 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Tuesday, 21st July 2020 11:27:05 am
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

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

nvm_content = init_nvm(40)

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

    def hook_ca_time(self, uc, address, size, user_data):
        if self.ca_range.start <= address < self.ca_range.stop:
            self.timer += 1

    def try_candidate(self, candidate_pin):
        print("Essai de %s :" %display_pin(candidate_pin), end=' ')
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

            self.ca_range = extract_symbol_range('compare_arrays', self.elf_path)
            # tracing instructions to measure time in verify_pin function
            mu.hook_add(UC_HOOK_CODE, self.hook_ca_time)

            #write the candidate PIN in io buffer
            mu.mem_write(self.INPUT_ADD, candidate_pin)

            # emulate machine code until timeout
            # Note we start at INST_ADDRESS | 1 to indicate THUMB mode.
            # mu.emu_start( start_address, end_address, timeout, nb_steps)
            mu.emu_start(self.INST_ADDRESS | 1, extract_symbol_address("_exit", self.elf_path), 1000000, 100000)

            nvm_content = bytes(mu.mem_read(self.NVM_ADDRESS, 1024))
            tries_left = nvm_content[0]

            verif_result = mu.mem_read(self.OUTPUT_ADD, 1)[0]
            
            if verif_result == 255:
                cprint("! PIN incorrect ! Essais restant: %i. Comparaison de tableaux réalisée en %i instructions" %(tries_left, self.timer), 'yellow')
            elif verif_result == 1:
                cprint("*** PIN accepté ***", 'green')
            elif verif_result == 2:
                cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
            else:
                print("Résultat inattendu: %i" %verif_result)

            return (verif_result, self.timer)

        except UcError as e:
            print("ERROR: %s" % e)

def find_secret(target_app_folder):
    pin_candidate = [0, 0, 0, 0]
    test_index = 0
    try_count = 0

    digit_timings = []#remember timings for current digit (index is equal to guess value)

    def choose_guess(timings):
        if not timings:
            return -1
        else:
            can_make_decision = False

            for i in range(len(timings)):
                for j in range(i+1, len(timings)):
                    if timings[i] == timings[j]:
                        can_make_decision = True
                        break
            if can_make_decision == False:
                return -1
            else:
                for i in range(len(timings)):
                    unique = True
                    for j in range(len(timings)):
                        if i != j and timings[i] == timings[j]:
                            unique = False
                    if unique == True:
                        return i
                return -1

    em = PINEmulator(target_app_folder)
    while test_index < 4:
        if pin_candidate[test_index] > 9:
            print("Impossible de trouver le PIN.")
            return (try_count, False)

        (res, timer) = em.try_candidate(bytes(pin_candidate))
        try_count += 1
        if res == 1:
            return (try_count, True) # we found it !
        elif res == 2:
            return (try_count, False) # carte vérouillée

        digit_timings.append(timer)
        selected_guess = choose_guess(digit_timings)

        if selected_guess != -1:
            pin_candidate[test_index] = selected_guess # assign selected guess
            test_index += 1 # lets go to next digit
            digit_timings = [digit_timings[selected_guess]]#we already know the timing for 0 since default PIN is [0, 0, 0, 0]
            if test_index < 4: 
                pin_candidate[test_index] += 1 #optimization to avoid double testing the guess 0
        else:
            pin_candidate[test_index] += 1

    return (try_count, True)
        
        

if __name__ == '__main__':
    target_app_folder = '.'
    if len(sys.argv) > 1:
        target_app_folder = sys.argv[1]

    target_app_folder = os.path.abspath(target_app_folder)

    (try_count, attack_success) = find_secret(target_app_folder)
    print("Attaque terminée après %i essais.\n" %try_count)

    if attack_success:
        sys.exit(1)
    else:
        sys.exit(0)