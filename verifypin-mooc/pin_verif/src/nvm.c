/*
 * File: nvm.h
 * Project: src
 * Created Date: Friday July 10th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Friday July 10th 2020 11:23:10 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

#include "nvm.h"
#include "ass.h"

#define COUNTER_ADD 0x50000000

void store_counter(uint32_t counter_value) {
    store_io(counter_value, (void*)COUNTER_ADD);
}

uint32_t load_counter() {
    return load_io((void*)COUNTER_ADD);
}