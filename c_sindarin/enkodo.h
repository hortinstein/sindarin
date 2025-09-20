#ifndef SINDARIN_ENKODO_H
#define SINDARIN_ENKODO_H

#include "types.h"
#include <stddef.h>

// Key generation
int generate_key_pair(Key* private_key, Key* public_key);

// Encryption/Decryption compatible with Nim's enkodo
int enc(const Key* sender_private_key, const Key* recipient_public_key, 
        const uint8_t* message, size_t message_len, EncObj* result);

int dec(const Key* private_key, const EncObj* enc_obj, 
        uint8_t** result, size_t* result_len);

// Key exchange functions for compatibility
int key_exchange_wrapper(const Key* private_key, const Key* public_key, Key* shared_key);

int crypto_key_exchange_public_key(const Key* private_key, Key* public_key);

// Utility functions
int b64_encode(const uint8_t* data, size_t len, char** result);
int b64_decode(const char* data, uint8_t** result, size_t* result_len);

// Serialization wrappers for EncObj
int wrap_enc_obj(const EncObj* enc_obj, char** result);
int unwrap_enc_obj(const char* wrapped, EncObj* result);

// Key wrapping
int wrap_key(const Key* key, char** result);
int unwrap_key(const char* wrapped, Key* result);

#endif // SINDARIN_ENKODO_H