#pragma once

#include <stdint.h>

void AuthCrypto_Encrypt(const uint8_t key[32], const uint8_t input[32], uint8_t output[32]);
void AuthCrypto_Digest(const uint8_t input[32], uint8_t output[32]);
