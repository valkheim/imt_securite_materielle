'''
File: machine.py
Project: Enonce
Created Date: Tuesday June 2nd 2020
Author: Ronan (ronan.lashermes@inria.fr)
-----
Last Modified: Wednesday, 14th October 2020 4:02:25 pm
Modified By: Ronan (ronan.lashermes@inria.fr>)
-----
Copyright (c) 2020 INRIA
'''
#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from unicorn import *
from unicorn.arm_const import *

import random

# from gmpy2 import popcount

from termcolor import colored, cprint

import numpy as np
import tensorflow as tf
from tensorflow import keras

# from sklearn.decomposition import PCA

import sys
import os
import gc

import binascii
from functools import partial

import multiprocessing
import tqdm

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

DIGITS = 4
LEARN_SIZE = 200000
CORE_MULTITHREADING = multiprocessing.cpu_count()

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


def gen_rand_pin():
    return bytes([random.randint(0,9) for _ in range(4)])

def parse_input_pin(input_pin_str):
    ascii_array = binascii.a2b_qp(input_pin_str)
    return bytes([elem - 0x30 for elem in ascii_array])

def display_pin(input_pin):
    return bytes([elem + 0x30 for elem in input_pin]).decode("utf-8") 

arm_regs = [UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_R13, UC_ARM_REG_R14, UC_ARM_REG_R15]
def leakage_model(uc):
    total_hw = 0
    for r in arm_regs:
        val = uc.reg_read(r)
        # total_hw += popcount(val)
        total_hw += val
    return total_hw


def init_nvm(nb_essais):
    content = bytearray([0 for _ in range(1024)])
    content[0] = nb_essais
    return bytes(content)

nvm_content = init_nvm(10)

class PINEmulator:
    # memory address where emulation starts
    INST_ADDRESS    = 0x8000000
    RAM_ADDRESS     = 0x20000000
    IO_ADDRESS      = 0x10000000
    NVM_ADDRESS     = 0x50000000

    INPUT_ADD       = 0x10000000
    OUTPUT_ADD      = 0x10000010

    def __init__(self, target_app_folder_path):
        self.bin_path = target_app_folder + '/pin.bin'
        self.elf_path = target_app_folder + '/pin.elf'
        self.THUMB_CODE = load_code(self.bin_path)


    # callback for tracing instructions
    def hook_code(self, uc, address, size, user_data):
        # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        self.trace.append(leakage_model(uc))

    def tracing(self, pin_candidate, pin_secret):
        global nvm_content
        self.timer = 0
        self.trace = []
        # try:
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

        # tracing instructions with customized callback
        compare_arrays_range = extract_symbol_range("compare_arrays", self.elf_path)
        verify_pin_range = extract_symbol_range("verify_pin", self.elf_path)

        mu.hook_add(UC_HOOK_CODE, self.hook_code, begin=compare_arrays_range.start, end=compare_arrays_range.stop)
        mu.hook_add(UC_HOOK_CODE, self.hook_code, begin=verify_pin_range.start, end=verify_pin_range.stop)

        #write the candidate PIN in io buffer
        mu.mem_write(self.IO_ADDRESS, pin_candidate)

        #overwrite secret pin
        if pin_secret[0] != 255:
            mu.mem_write(extract_symbol_address("secret_pin", self.elf_path), pin_secret)
        
        mu.emu_start(self.INST_ADDRESS | 1, extract_symbol_address("_exit", self.elf_path), 100000, 10000)
        leakage_model(mu)

        nvm_content_output = bytes(mu.mem_read(self.NVM_ADDRESS, 1024))
        tries_left = nvm_content_output[0]

        if pin_secret[0] == 255:
            nvm_content = nvm_content_output
        

        verif_result = mu.mem_read(self.OUTPUT_ADD, 1)[0]

        # map 128kiB of flash memory for the code
        mu.mem_unmap(self.INST_ADDRESS, 128 * 1024)
        # map 8kiB of ram memory
        mu.mem_unmap(self.RAM_ADDRESS, 8 * 1024)
        # map 1kiB for Non Volatile Memory (NVM)
        mu.mem_unmap(self.NVM_ADDRESS, 1 * 1024)
        # map 1kiB for IO buffer
        mu.mem_unmap(self.IO_ADDRESS, 1 * 1024)

        # print(self.trace)
        return (self.trace, verif_result, tries_left)

        # except UcError as e:
        #     print("ERROR: %s" % e)
        #     return [0]

def one_hot_pin_byte(byte_val):
    a = np.zeros(10)
    a[byte_val] = 1
    return a

# choose the best value from a probability vector
def pin_vector2value(pin_vector):
    max_val = 0
    max_ind = 0

    for i in range(pin_vector.shape[0]):
        if pin_vector[i] > max_val:
            max_val = pin_vector[i]
            max_ind = i
    
    return max_ind

def determine_max_trace_length(target_app_folder, iterations):
    em = PINEmulator(target_app_folder)

    max_len = 0

    for _ in range(iterations):
        l = len(em.tracing(gen_rand_pin(), gen_rand_pin())[0])
        if l > max_len:
            max_len = l

    l = len(em.tracing(bytes([0, 0, 0, 0]), bytes([0,0,0,0]))[0])
    if l > max_len:
        max_len = l

    return l+5

def get_ref_trace(target_app_folder, expected_trace_len):
    pin_candidate = bytes([0, 0, 0, 0])
    pin_secret = bytes([9, 9, 9, 9])
    em = PINEmulator(target_app_folder)
    new_trace = em.tracing(pin_candidate, pin_secret)[0]
    padded_trace = np.pad(new_trace, (0, expected_trace_len - len(new_trace)), mode='constant', constant_values=0)
    return padded_trace
    

def rand_learn_pair_data_aux(expected_trace_len,ref_trace,i):
    pin_candidate = gen_rand_pin()
    pin_secret = gen_rand_pin()

    em = PINEmulator(target_app_folder)
    new_trace = em.tracing(pin_candidate, pin_secret)[0]
    if len(new_trace) > expected_trace_len:
        print("ERROR: trace length is %i where expected length should be less then %i" %(len(new_trace), expected_trace_len))
        return (0, 0)
    
    padded_trace = np.pad(new_trace, (0, expected_trace_len - len(new_trace)), mode='constant', constant_values=0)
    padded_trace = padded_trace - ref_trace
    ltrace = padded_trace
    ltruths = [one_hot_pin_byte(pin_secret[tb]) for tb in range(DIGITS)]
    return (ltrace,ltruths)

def rand_learn_pair_data(target_app_folder, learning_size):

    
    expected_trace_len = determine_max_trace_length(target_app_folder, 100)

    ref_trace = get_ref_trace(target_app_folder, expected_trace_len)

    with multiprocessing.Pool(CORE_MULTITHREADING) as pool:
    # call the function for each item in parallel
        res = list(tqdm.tqdm(pool.imap(partial(rand_learn_pair_data_aux,expected_trace_len,ref_trace), range(learning_size)),total=learning_size))
    
    tmp = list(zip(*res))
    traces = np.asarray(tmp[0])
    truths = np.swapaxes(np.asarray(tmp[1]),0,1)
    return (traces, truths)


def build_keras_model(trace_len):
    inputs = keras.Input(trace_len)
    x = keras.layers.Dense(100, activation="relu")(inputs)
    outputs = keras.layers.Dense(10, activation="softmax")(x)
    model = keras.Model(inputs, outputs)
    model.compile(optimizer='rmsprop', loss='categorical_crossentropy')
    
    return model


if __name__ == '__main__':
    target_app_folder = '.'

    if len(sys.argv) > 1:
        target_app_folder = sys.argv[1]

    target_app_folder = os.path.abspath(target_app_folder) + "/bin"

    # do we load the model from files ? Or do we generate everything again
    load = False

    if len(sys.argv) > 2 and sys.argv[2] == "--load":
        load = True

    em = PINEmulator(target_app_folder)


    if load == False:
        (learn_traces, learn_truths) = rand_learn_pair_data(target_app_folder, LEARN_SIZE)
        np.save("learn_traces.npy", learn_traces)
        np.save("learn_truths.npy", learn_truths)
    else:
        learn_traces = np.load("learn_traces.npy")
        learn_truths = np.load("learn_truths.npy")

    dl_len = learn_traces.shape[1]




    m = []
    for d in range(DIGITS):
        if load == False:
            new_model = build_keras_model(dl_len)
            new_model.fit(learn_traces, learn_truths[d], epochs=10)
            new_model.save("m{}.km".format(d))
            m.append(new_model)
        else:
            new_model = keras.models.load_model("m{}.km".format(d))
            m.append(new_model)
        

    ref_trace = get_ref_trace(target_app_folder, dl_len)

    attack_success = False
    pin_code = ''.join(random.choices('0123456789', k=4))
    candidate_pin = parse_input_pin(pin_code)

    max_tries = 50

    while max_tries > 0:
        max_tries -= 1
        print("> Testing PIN: %s" %display_pin(candidate_pin));
        
         # input as bytes

        (new_trace, verif_result, tries_left) = em.tracing(candidate_pin, bytes([255,0,0,0]))

        # trace transformation (padding in diff with ref)
        padded_trace = np.pad(new_trace, (0, dl_len - len(new_trace)), mode='constant', constant_values=0)
        padded_trace = np.expand_dims(padded_trace - ref_trace, axis=0)

        if verif_result == 255:
            cprint("! PIN incorrect ! Essais restant: %i" %tries_left, 'yellow')
        elif verif_result == 1:
            cprint("*** PIN accepté *** Essais restant: %i" %tries_left, 'green')
            attack_success = True
            break
        elif verif_result == 2:
            cprint("!! Carte vérouillée !! Essais restant: %i" %tries_left, 'red')
            break
        else:
            print("Résultat inattendu: %i" %verif_result)
            break

        best_pin = []
        for i in range(DIGITS):
            predict = m[i].predict(padded_trace)
            best_digit = pin_vector2value(predict[0])
            best_pin.append(best_digit)
        
        best_pin = bytes(best_pin)
        cprint("Best PIN prediction: %s" %display_pin(best_pin))
        candidate_pin = best_pin
        
    if attack_success:
        sys.exit(1)
    else:
        sys.exit(0)

    # predicts = m.predict(test_traces)

    # for i in range(predicts.shape[0]):
    #     predicts[i] = list(map(lambda x: round(x, 2), predicts[i]))
