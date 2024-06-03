/*
 * File: pin.h
 * Project: target_app
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Tuesday, 21st July 2020 10:54:56 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

#ifndef PIN_H
#define PIN_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define PIN_SIZE 4

#define LOCKED 2
#define VALID 1
#define UNDER_ATTACK 10
#define INVALID 255

#define ARRACHER_ICI __asm("arrache:");

bool compare_arrays(const uint8_t* a, const uint8_t* b, size_t len);
int verify_pin(const uint8_t* to_verify, size_t len);

#endif