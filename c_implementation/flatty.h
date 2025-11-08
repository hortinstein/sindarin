/**
 * Flatty serialization/deserialization compatible with Nim's Flatty library
 */

#ifndef FLATTY_H
#define FLATTY_H

#include "types.h"
#include <stddef.h>

// Serialization functions
size_t serialize_key(const Key* key, uint8_t* buffer);
size_t serialize_enc_obj(const EncObj* obj, uint8_t* buffer);
size_t serialize_enc_config(const EncConfig* config, uint8_t* buffer);
size_t serialize_static_config(const StaticConfig* config, uint8_t* buffer);
size_t serialize_status(const Status* status, uint8_t* buffer);
size_t serialize_callback(const Callback* callback, uint8_t* buffer);
size_t serialize_task(const Task* task, uint8_t* buffer);
size_t serialize_resp(const Resp* resp, uint8_t* buffer);

// Deserialization functions (return bytes consumed, or 0 on error)
size_t deserialize_key(const uint8_t* buffer, size_t buffer_len, Key* key);
size_t deserialize_enc_obj(const uint8_t* buffer, size_t buffer_len, EncObj* obj);
size_t deserialize_enc_config(const uint8_t* buffer, size_t buffer_len, EncConfig* config);
size_t deserialize_static_config(const uint8_t* buffer, size_t buffer_len, StaticConfig* config);
size_t deserialize_status(const uint8_t* buffer, size_t buffer_len, Status* status);
size_t deserialize_callback(const uint8_t* buffer, size_t buffer_len, Callback* callback);
size_t deserialize_task(const uint8_t* buffer, size_t buffer_len, Task* task);
size_t deserialize_resp(const uint8_t* buffer, size_t buffer_len, Resp* resp);

// Helper functions for primitives
size_t serialize_string(const char* str, uint8_t* buffer);
size_t deserialize_string(const uint8_t* buffer, size_t buffer_len, char** str);
size_t serialize_int32(int32_t value, uint8_t* buffer);
size_t deserialize_int32(const uint8_t* buffer, int32_t* value);
size_t serialize_int64(int64_t value, uint8_t* buffer);
size_t deserialize_int64(const uint8_t* buffer, int64_t* value);
size_t serialize_bool(bool value, uint8_t* buffer);
size_t deserialize_bool(const uint8_t* buffer, bool* value);
size_t serialize_bytes(const uint8_t* data, size_t len, uint8_t* buffer);
size_t deserialize_bytes(const uint8_t* buffer, size_t buffer_len, uint8_t** data, size_t* len);

// Calculate serialized sizes (for buffer allocation)
size_t calc_enc_obj_size(const EncObj* obj);
size_t calc_enc_config_size(const EncConfig* config);
size_t calc_static_config_size(const StaticConfig* config);
size_t calc_status_size(const Status* status);
size_t calc_callback_size(const Callback* callback);
size_t calc_task_size(const Task* task);
size_t calc_resp_size(const Resp* resp);

#endif // FLATTY_H
