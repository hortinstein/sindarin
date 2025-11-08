/**
 * Encryption/decryption using Monocypher
 * Compatible with Nim's enkodo library
 */

#ifndef ENKODO_H
#define ENKODO_H

#include "types.h"
#include <stddef.h>

// Key generation
int generate_key_pair(Key* private_key, Key* public_key);

// Encryption/decryption
int enc(const Key* sender_private_key, const Key* recipient_public_key,
        const uint8_t* message, size_t message_len, EncObj* enc_obj);

int dec(const Key* private_key, const EncObj* enc_obj,
        uint8_t** plaintext, size_t* plaintext_len);

// Helper functions
int crypto_key_exchange_public_key(const Key* private_key, Key* public_key);

// Base64 encoding/decoding
char* b64_encode(const uint8_t* data, size_t len);
uint8_t* b64_decode(const char* str, size_t* out_len);

// Wrapper functions for EncObj
char* wrap_enc_obj(const EncObj* enc_obj);
int unwrap_enc_obj(const char* b64_str, EncObj* enc_obj);

// File I/O
int write_bytes_to_file(const char* filename, const uint8_t* data, size_t len);
uint8_t* read_bytes_from_file(const char* filename, size_t* out_len);

#endif // ENKODO_H
