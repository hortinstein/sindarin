/**
 * Encryption/decryption implementation using Monocypher
 */

#include "enkodo.h"
#include "flatty.h"
#include "monocypher.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// Random number generation for key/nonce generation
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
static int get_random_bytes(uint8_t* buffer, size_t len) {
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptGenRandom(hCryptProv, (DWORD)len, buffer)) {
        CryptReleaseContext(hCryptProv, 0);
        return -1;
    }
    CryptReleaseContext(hCryptProv, 0);
    return 0;
}
#else
#include <unistd.h>
#include <fcntl.h>
static int get_random_bytes(uint8_t* buffer, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t result = read(fd, buffer, len);
    close(fd);
    return (result == (ssize_t)len) ? 0 : -1;
}
#endif

// Generate a key pair
int generate_key_pair(Key* private_key, Key* public_key) {
    // Generate random private key
    if (get_random_bytes(private_key->data, KEY_SIZE) != 0) {
        return -1;
    }

    // Derive public key from private key
    crypto_x25519_public_key(public_key->data, private_key->data);

    return 0;
}

// Get public key from private key
int crypto_key_exchange_public_key(const Key* private_key, Key* public_key) {
    crypto_x25519_public_key(public_key->data, private_key->data);
    return 0;
}

// Encrypt message
int enc(const Key* sender_private_key, const Key* recipient_public_key,
        const uint8_t* message, size_t message_len, EncObj* enc_obj) {

    // Generate random nonce
    if (get_random_bytes(enc_obj->nonce.data, NONCE_SIZE) != 0) {
        return -1;
    }

    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, sender_private_key->data, recipient_public_key->data);

    // Allocate ciphertext buffer
    enc_obj->cipherText = (uint8_t*)malloc(message_len);
    if (!enc_obj->cipherText) {
        return -1;
    }
    enc_obj->cipherLen = message_len;

    // Encrypt using monocypher's aead_lock function
    crypto_aead_lock(enc_obj->cipherText, enc_obj->mac.data,
                     shared_key, enc_obj->nonce.data,
                     NULL, 0,  // no additional data
                     message, message_len);

    // Get sender's public key
    crypto_x25519_public_key(enc_obj->publicKey.data, sender_private_key->data);

    // Wipe shared key from memory
    crypto_wipe(shared_key, sizeof(shared_key));

    return 0;
}

// Decrypt EncObj
int dec(const Key* private_key, const EncObj* enc_obj,
        uint8_t** plaintext, size_t* plaintext_len) {

    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, private_key->data, enc_obj->publicKey.data);

    // Allocate plaintext buffer
    *plaintext = (uint8_t*)malloc(enc_obj->cipherLen);
    if (!*plaintext) {
        crypto_wipe(shared_key, sizeof(shared_key));
        return -1;
    }
    *plaintext_len = enc_obj->cipherLen;

    // Decrypt using monocypher's aead_unlock function
    int result = crypto_aead_unlock(*plaintext, enc_obj->mac.data,
                                   shared_key, enc_obj->nonce.data,
                                   NULL, 0,  // no additional data
                                   enc_obj->cipherText, enc_obj->cipherLen);

    // Wipe shared key from memory
    crypto_wipe(shared_key, sizeof(shared_key));

    if (result != 0) {
        // Decryption failed (MAC mismatch)
        free(*plaintext);
        *plaintext = NULL;
        *plaintext_len = 0;
        return -1;
    }

    return 0;
}

// Base64 encoding table (URL-safe)
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char* b64_encode(const uint8_t* data, size_t len) {
    size_t output_len = ((len + 2) / 3) * 4;
    char* output = (char*)malloc(output_len + 1);
    if (!output) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >> 6) & 0x3F];
        output[j++] = base64_chars[triple & 0x3F];
    }

    // Handle padding
    size_t padding = (3 - (len % 3)) % 3;
    for (size_t p = 0; p < padding; p++) {
        output[output_len - 1 - p] = '=';
    }

    output[output_len] = '\0';
    return output;
}

static int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

uint8_t* b64_decode(const char* str, size_t* out_len) {
    size_t len = strlen(str);
    while (len > 0 && str[len - 1] == '=') len--;

    size_t output_len = (len * 3) / 4;
    uint8_t* output = (uint8_t*)malloc(output_len);
    if (!output) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t sextet_a = i < len ? base64_char_value(str[i++]) : 0;
        uint32_t sextet_b = i < len ? base64_char_value(str[i++]) : 0;
        uint32_t sextet_c = i < len ? base64_char_value(str[i++]) : 0;
        uint32_t sextet_d = i < len ? base64_char_value(str[i++]) : 0;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) +
                         (sextet_c << 6) + sextet_d;

        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }

    *out_len = output_len;
    return output;
}

// Wrap EncObj as base64 string
char* wrap_enc_obj(const EncObj* enc_obj) {
    // Calculate buffer size needed
    size_t buffer_size = calc_enc_obj_size(enc_obj);
    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    if (!buffer) return NULL;

    // Serialize EncObj
    size_t serialized_size = serialize_enc_obj(enc_obj, buffer);

    // Base64 encode
    char* b64_str = b64_encode(buffer, serialized_size);

    free(buffer);
    return b64_str;
}

// Unwrap base64 string to EncObj
int unwrap_enc_obj(const char* b64_str, EncObj* enc_obj) {
    size_t buffer_len;
    uint8_t* buffer = b64_decode(b64_str, &buffer_len);
    if (!buffer) return -1;

    size_t bytes_read = deserialize_enc_obj(buffer, buffer_len, enc_obj);
    free(buffer);

    return bytes_read > 0 ? 0 : -1;
}

// File I/O helpers
int write_bytes_to_file(const char* filename, const uint8_t* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) return -1;

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    return (written == len) ? 0 : -1;
}

uint8_t* read_bytes_from_file(const char* filename, size_t* out_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;

    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0) {
        fclose(f);
        return NULL;
    }

    // Allocate buffer
    uint8_t* buffer = (uint8_t*)malloc(file_size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    // Read file
    size_t bytes_read = fread(buffer, 1, file_size, f);
    fclose(f);

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return NULL;
    }

    *out_len = file_size;
    return buffer;
}
