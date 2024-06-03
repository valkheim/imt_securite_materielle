/*
 * File: nvm.h
 * Project: src
 * Created Date: Friday July 10th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Friday July 10th 2020 11:21:02 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

#ifndef NVM_H
#define NVM_H

#include <stdint.h>

#define NVM_ADDRESS 0x50000000

void        store_counter(uint32_t counter_value);
uint32_t    load_counter();

#endif