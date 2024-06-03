/*
 * File: pin.c
 * Project: target_app
 * Created Date: Monday May 25th 2020
 * Author: Ronan (ronan.lashermes@inria.fr)
 * -----
 * Last Modified: Tuesday, 21st July 2020 10:54:38 am
 * Modified By: Ronan (ronan.lashermes@inria.fr>)
 * -----
 * Copyright (c) 2020 INRIA
 */

#include "pin.h"
#include "nvm.h"
#include "hmac-sha256.h"

#define COUNTER_MAX 3

//this is the secret pin value
// const uint8_t secret_pin[4] = {0,0,4,2};
const uint8_t secret_key[] = "secret";
const uint8_t secret_pin[] = {0xac, 0x3a, 0xa4, 0x9f, 0x96, 0x34, 0x81, 0xfd, 0x46, 0x6f, 0x4b, 0xb6, 0x58, 0x78, 0x31, 0x32, 0x22, 0x57, 0x4c, 0x75, 0x5a, 0xdb, 0x72, 0x33, 0x28, 0x9d, 0x75, 0x7f, 0xfe, 0x8c, 0xef, 0x52};

bool compare_arrays(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t ok = 0;
    volatile uint8_t ok_v = 0;

    // Instead of using the clear secret_pin, we use a sha256 hash so the original pin is not exposed
    uint8_t encoded[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(encoded, a, len, secret_key, sizeof(secret_key));

    for (int i = 0; i < PIN_SIZE; i++)
    {
        // assume const time xor
        ok |= encoded[i] ^ b[i];
    }

    ok_v = ok;
    return ok == 0 && ok_v == 0;
}

int verify_pin(const uint8_t* to_verify, size_t len) {
    // Use counter to prevent brute force
    volatile uint32_t counter_1 = load_counter();
    if (counter_1 == 0) {
        return LOCKED;
    }

    // Use code duplication to mitigate fault injections
    volatile uint32_t counter_2 = load_counter();
    if (counter_2 == 0) {
        return LOCKED;
    }

    // Decrement before comparing to prevent tearing-off
    counter_1--;
    counter_2--;
    if (counter_1 != counter_2) {
        return UNDER_ATTACK;
    }

    store_counter(counter_1);
    store_counter(counter_2);

    if (len != PIN_SIZE) {
        return UNDER_ATTACK;
    }

    // Compare with a MAC to avoid storing secret which can be leaked (as in a power analysis scheme)
    volatile bool const ok_1 = compare_arrays(to_verify, (uint8_t *)&secret_pin, PIN_SIZE);
    volatile bool const ok_2 = compare_arrays(to_verify, (uint8_t *)&secret_pin, PIN_SIZE);
    if (!ok_1 || !ok_2) {
        ARRACHER_ICI;
    }

    if (!ok_1) {
        return INVALID;
    }

    if (!ok_2) {
        return INVALID;
    }

    counter_1 = COUNTER_MAX;
    counter_2 = COUNTER_MAX;
    if (counter_1 != counter_2) {
        return UNDER_ATTACK;
    }

    store_counter(counter_1);
    store_counter(counter_2);
    return VALID;
}