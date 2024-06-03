/*
 * File: start.S
 * Project: src
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Monday, 25th May 2020 1:35:57 pm
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

.cpu cortex-m3
.thumb

.section .isr_vector
.globl Reset_Handler

Reset_Handler:
    b _mainCRTStartup
    