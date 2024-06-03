/*
 * File: ass.s
 * Project: src
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Friday, 29th May 2020 9:51:12 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

.cpu cortex-m3
.thumb

.section .text
.globl store_io
.globl load_io

store_io:
    str     r0, [r1]
    bx      lr

load_io:
    ldr     r0, [r0]
    bx      lr
    
