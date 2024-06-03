/*
 * File: ass.h
 * Project: src
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Friday, 29th May 2020 9:50:02 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

#ifndef ASS_H
#define ASS_H

#include <stdint.h>

extern void store_io(uint32_t val, void* add);
extern uint32_t load_io(void* add);


#endif