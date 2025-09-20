#include "enkodo.h"
#include "flatty.h"
#include "monocypher.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// Generate random bytes for key generation
static int generate_random_bytes(uint8_t* buffer, size_t len) {
    FILE* fp = fopen("/dev/urandom", "rb");
    if (!fp) return -1;
    
    size_t bytes_read = fread(buffer, 1, len, fp);
    fclose(fp);
    
    return (bytes_read == len) ? 0 : -1;
}

// Key generation compatible with Nim/Python
int generate_key_pair(Key* private_key, Key* public_key) {
    if (!private_key || !public_key) return -1;
    
    // Generate random private key
    if (generate_random_bytes(private_key->data, 32) != 0) {
        return -1;
    }
    
    // Derive public key from private key
    crypto_x25519_public_key(public_key->data, private_key->data);
    
    return 0;
}

// Encrypt message compatible with Nim's enkodo.enc
int enc(const Key* sender_private_key, const Key* recipient_public_key, 
        const uint8_t* message, size_t message_len, EncObj* result) {
    if (!sender_private_key || !recipient_public_key || !message || !result) {
        return -1;
    }
    
    // Generate random nonce (24 bytes)
    if (generate_random_bytes(result->nonce.data, 24) != 0) {
        return -1;
    }
    
    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, sender_private_key->data, recipient_public_key->data);
    
    // Allocate ciphertext buffer
    result->cipherText = malloc(message_len);
    if (!result->cipherText) {
        return -1;
    }
    result->cipherLen = message_len;
    
    // Encrypt using monocypher's aead_lock function (no associated data)
    crypto_aead_lock(result->cipherText, result->mac.data, shared_key, result->nonce.data, 
                     NULL, 0, message, message_len);
    
    // Get the public key for the sender's private key
    crypto_x25519_public_key(result->publicKey.data, sender_private_key->data);
    
    // Clear shared key from memory
    crypto_wipe(shared_key, 32);
    
    return 0;
}

// Decrypt EncObj compatible with Nim's enkodo.dec
int dec(const Key* private_key, const EncObj* enc_obj, 
        uint8_t** result, size_t* result_len) {
    if (!private_key || !enc_obj || !result || !result_len) {
        return -1;
    }
    
    *result = NULL;
    *result_len = 0;
    
    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, private_key->data, enc_obj->publicKey.data);
    
    // Allocate plaintext buffer
    *result = malloc(enc_obj->cipherLen);
    if (!*result) {
        crypto_wipe(shared_key, 32);
        return -1;
    }
    
    // Decrypt using monocypher's aead_unlock function (no associated data)
    int unlock_result = crypto_aead_unlock(*result, enc_obj->mac.data, shared_key, enc_obj->nonce.data,
                                          NULL, 0, enc_obj->cipherText, enc_obj->cipherLen);
    
    // Clear shared key from memory
    crypto_wipe(shared_key, 32);
    
    if (unlock_result != 0) {
        // Decryption failed
        free(*result);
        *result = NULL;
        return -1;
    }
    
    *result_len = enc_obj->cipherLen;
    return 0;
}

// Key exchange functions for compatibility
int key_exchange_wrapper(const Key* private_key, const Key* public_key, Key* shared_key) {
    if (!private_key || !public_key || !shared_key) return -1;
    
    crypto_x25519(shared_key->data, private_key->data, public_key->data);
    return 0;
}

int crypto_key_exchange_public_key(const Key* private_key, Key* public_key) {
    if (!private_key || !public_key) return -1;
    
    crypto_x25519_public_key(public_key->data, private_key->data);
    return 0;
}

// Base64 encoding/decoding utilities
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char base64_pad = '=';

int b64_encode(const uint8_t* data, size_t len, char** result) {
    if (!data || !result) return -1;
    
    size_t output_len = ((len + 2) / 3) * 4;
    *result = malloc(output_len + 1);
    if (!*result) return -1;
    
    size_t i, j;
    uint32_t triple;
    
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        triple = (data[i] << 16) | 
                 (i + 1 < len ? data[i + 1] << 8 : 0) | 
                 (i + 2 < len ? data[i + 2] : 0);
        
        (*result)[j] = base64_table[(triple >> 18) & 0x3F];
        (*result)[j + 1] = base64_table[(triple >> 12) & 0x3F];
        (*result)[j + 2] = (i + 1 < len) ? base64_table[(triple >> 6) & 0x3F] : base64_pad;
        (*result)[j + 3] = (i + 2 < len) ? base64_table[triple & 0x3F] : base64_pad;
    }
    
    (*result)[output_len] = '\0';
    return 0;
}

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int b64_decode(const char* data, uint8_t** result, size_t* result_len) {
    if (!data || !result || !result_len) return -1;
    
    size_t input_len = strlen(data);
    if (input_len % 4 != 0) return -1;
    
    size_t output_len = (input_len / 4) * 3;
    if (input_len >= 1 && data[input_len - 1] == base64_pad) output_len--;
    if (input_len >= 2 && data[input_len - 2] == base64_pad) output_len--;
    
    *result = malloc(output_len);
    if (!*result) return -1;
    
    size_t i, j;
    uint32_t quad;
    
    for (i = 0, j = 0; i < input_len; i += 4, j += 3) {
        int c1 = base64_decode_char(data[i]);
        int c2 = base64_decode_char(data[i + 1]);
        int c3 = (data[i + 2] != base64_pad) ? base64_decode_char(data[i + 2]) : 0;
        int c4 = (data[i + 3] != base64_pad) ? base64_decode_char(data[i + 3]) : 0;
        
        if (c1 < 0 || c2 < 0 || (data[i + 2] != base64_pad && c3 < 0) || 
            (data[i + 3] != base64_pad && c4 < 0)) {
            free(*result);
            *result = NULL;
            return -1;
        }
        
        quad = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
        
        if (j < output_len) (*result)[j] = (quad >> 16) & 0xFF;
        if (j + 1 < output_len) (*result)[j + 1] = (quad >> 8) & 0xFF;
        if (j + 2 < output_len) (*result)[j + 2] = quad & 0xFF;
    }
    
    *result_len = output_len;
    return 0;
}

// Serialization wrappers
int wrap_enc_obj(const EncObj* enc_obj, char** result) {
    if (!enc_obj || !result) return -1;
    
    uint8_t* serialized;
    size_t serialized_len;
    
    if (to_flatty_enc_obj(enc_obj, &serialized, &serialized_len) != 0) {
        return -1;
    }
    
    int ret = b64_encode(serialized, serialized_len, result);
    free(serialized);
    return ret;
}

int unwrap_enc_obj(const char* wrapped, EncObj* result) {
    if (!wrapped || !result) return -1;
    
    uint8_t* decoded;
    size_t decoded_len;
    
    if (b64_decode(wrapped, &decoded, &decoded_len) != 0) {
        return -1;
    }
    
    size_t bytes_consumed;
    int ret = from_flatty_enc_obj(decoded, decoded_len, result, &bytes_consumed);
    free(decoded);
    return ret;
}

int wrap_key(const Key* key, char** result) {
    if (!key || !result) return -1;
    
    uint8_t* serialized;
    size_t serialized_len;
    
    if (to_flatty_key(key, &serialized, &serialized_len) != 0) {
        return -1;
    }
    
    int ret = b64_encode(serialized, serialized_len, result);
    free(serialized);
    return ret;
}

int unwrap_key(const char* wrapped, Key* result) {
    if (!wrapped || !result) return -1;
    
    uint8_t* decoded;
    size_t decoded_len;
    
    if (b64_decode(wrapped, &decoded, &decoded_len) != 0) {
        return -1;
    }
    
    int ret = from_flatty_key(decoded, decoded_len, result);
    free(decoded);
    return ret;
}