'''
File: machine.py
Project: Enonce
Created Date: Tuesday June 2nd 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Thursday, 30th July 2020 11:24:19 am
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from unicorn import *
from unicorn.arm_const import *

from termcolor import colored, cprint

import sys
import os

import binascii
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

# we read the elf file to automatically extract the address and size of the given symbol
def extract_symbol_range(symbol_name, elf_path):
    e = ELFFile(open(elf_path, 'rb'))
    symbol_tables = [s for s in e.iter_sections() if isinstance(s, SymbolTableSection)]
    for section in symbol_tables:
        for symbol in section.iter_symbols():
            if symbol.name == symbol_name:
                sstart = symbol['st_value'] & 0xFFFFFFFE
                send = symbol['st_size'] + symbol['st_value'] & 0xFFFFFFFE

                return range(sstart, send)

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

MAX_FAULTS = 1

class PINEmulator:

    # memory address where emulation starts
    INST_ADDRESS    = 0x8000000
    RAM_ADDRESS     = 0x20000000
    IO_ADDRESS      = 0x10000000
    NVM_ADDRESS     = 0x50000000

    INPUT_ADD       = 0x10000000
    OUTPUT_ADD      = 0x10000010

    # self.fault_count = 0

    def __init__(self, target_app_folder_path):
        self.bin_path = target_app_folder + '/bin/pin.bin'
        self.elf_path = target_app_folder + '/bin/pin.elf'
        self.THUMB_CODE = load_code(self.bin_path)

    def skip_at(self, uc, skip_address):
        uc.hook_add(UC_HOOK_CODE, self.hook_skip, None, skip_address, skip_address)

    def hook_skip(self, uc, address, isize, user_data):
        # print(">>> Skip instruction at 0x%x, instruction size = 0x%x -> new PC = 0x%x" %(address, isize, (address + isize)))
        if self.fault_count < MAX_FAULTS:
            uc.reg_write(UC_ARM_REG_PC, (address + isize) | 1)
            self.fault_count += 1

    def execute(self, fault_address, candidate_pin):
        global nvm_content
        self.fault_count = 0
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

            # where to inject fault
            self.skip_at(mu, fault_address)

            #write the candidate PIN in io buffer
            mu.mem_write(self.INPUT_ADD,candidate_pin)
            # mu.mem_write(self.INPUT_ADD, bytes([3,1,4,1]))

            # emulate machine code until timeout
            # Note we start at INST_ADDRESS | 1 to indicate THUMB mode.
            # mu.emu_start( start_address, end_address, timeout, nb_steps)
            mu.emu_start(self.INST_ADDRESS | 1, extract_symbol_address("_exit", self.elf_path), 100000, 10000)
            verif_result = mu.mem_read(self.OUTPUT_ADD, 1)

            nvm_content_output = bytes(mu.mem_read(self.NVM_ADDRESS, 1024))
            tries_left = nvm_content_output[0]

            

            return (verif_result[0], tries_left)

        except UcError as e:
            # print("ERROR: %s" % e)
            return (0, 0)

def test_all_pin(targeted_address, target_app_folder):
    print("")
    for b1 in range(10):
        for b2 in range(10):
            for b3 in range(10):
                for b4 in range(10):
                    pin_candidate = bytes([b1, b2, b3, b4])
                    print("\rTesting %i%i%i%i:" %(b1, b2, b3, b4), end=' ')
                    
                    em = PINEmulator(target_app_folder)
                    (verif_result, tries_left) = em.execute(targeted_address, pin_candidate)

                    if verif_result == 255:
                        cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow', end = '')
                    elif verif_result == 1:
                        cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
                    elif verif_result == 2:
                        cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
                    elif verif_result == 10:
                        cprint("!! Carte attaquée !! Essais restant: %i" %tries_left, 'blue')
                    else:
                        print("Résultat inattendu: %i" %verif_result)

                    if verif_result == 1:
                        return True
                    elif verif_result != 255:
                        return False
    return False



def fault_range(address_range, target_app_folder):    
    for add in address_range:
        if add % 2 == 0:
            print("Faute à l'addresse 0x%x: " %add, end='')
            em = PINEmulator(target_app_folder)
            (verif_result, tries_left) = em.execute(add, bytes([0,0,0,0]))

            if verif_result == 255:
                cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow')
            elif verif_result == 1:
                cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
            elif verif_result == 2:
                cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
            elif verif_result == 10:
                cprint("!! Carte attaquée !! Essais restant: %i" %tries_left, 'blue')
            else:
                print("Résultat inattendu: %i" %verif_result)
        
def intersection(a, b): 
    return [val for val in a if val in b]


def find_target_for_counter_attack(symbol_name, target_app_folder_path):
    elf_path = target_app_folder + '/bin/pin.elf'
    address_range = extract_symbol_range(symbol_name, elf_path)

    target_counter = []
    for add in address_range:
        if add % 2 == 0:
            em = PINEmulator(target_app_folder_path)
            (_, tries_left) = em.execute(add, bytes([0,0,0,0]))

            if tries_left > 2:
                target_counter.append(add)

    print("Cibles pour une attaque sur le compteur ("+ symbol_name +"):")
    for t in target_counter:
        print("\t0x%x" %t)


    return target_counter
        
def brute_force_targets(targets, target_app_folder):
    if len(targets) > 0:
        for target in targets:
            print("Utilisation de 0x%x comme cible de la faute." %target)
            success = test_all_pin(target, target_app_folder)
            print("")

            if success == True:
                return True
    else:
        print("Pas de cible trouvée pour attaquer le compteur")

    return False


if __name__ == '__main__':
    target_app_folder = '.'

    if len(sys.argv) > 1:
        target_app_folder = sys.argv[1]

    target_app_folder = os.path.abspath(target_app_folder)
    elf_path = target_app_folder + '/bin/pin.elf'

    targets = find_target_for_counter_attack("verify_pin", target_app_folder)
    # targets.extend(find_target_for_counter_attack("compare_arrays", target_app_folder))

    attack_success = brute_force_targets(targets, target_app_folder)

    if attack_success:
        sys.exit(1)
    else:
        sys.exit(0)
