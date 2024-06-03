/*
 * File: main.c
 * Project: target_app
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Tuesday, 21st July 2020 10:55:04 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */


#include "pin.h"
#include "ass.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define INPUT_ADD 0x10000000
#define OUTPUT_ADD 0x10000010

void main(void) {    
    //candidate PIN is expected at 0x10000000.
    int verif_result = verify_pin((void *)INPUT_ADD, PIN_SIZE);
    store_io(verif_result, (void*)OUTPUT_ADD);
}
