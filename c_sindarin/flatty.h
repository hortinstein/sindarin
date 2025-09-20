#ifndef SINDARIN_FLATTY_H
#define SINDARIN_FLATTY_H

#include "types.h"
#include <stddef.h>

// Binary serialization compatible with Nim's flatty library

// Basic type serialization
int serialize_string(const char* str, uint8_t** result, size_t* result_len);
int deserialize_string(const uint8_t* data, size_t data_len, size_t offset, 
                      char** result, size_t* new_offset);

int serialize_int32(int32_t value, uint8_t** result, size_t* result_len);
int deserialize_int32(const uint8_t* data, size_t data_len, size_t offset, 
                     int32_t* result, size_t* new_offset);

int serialize_int64(int64_t value, uint8_t** result, size_t* result_len);
int deserialize_int64(const uint8_t* data, size_t data_len, size_t offset, 
                     int64_t* result, size_t* new_offset);

int serialize_bool(int value, uint8_t** result, size_t* result_len);
int deserialize_bool(const uint8_t* data, size_t data_len, size_t offset, 
                    int* result, size_t* new_offset);

int serialize_bytes(const uint8_t* data, size_t len, uint8_t** result, size_t* result_len);
int deserialize_bytes(const uint8_t* data, size_t data_len, size_t offset, 
                     uint8_t** result, size_t* result_bytes_len, size_t* new_offset);

// Complex type serialization
int to_flatty_key(const Key* key, uint8_t** result, size_t* result_len);
int from_flatty_key(const uint8_t* data, size_t data_len, Key* result);

int to_flatty_enc_obj(const EncObj* enc_obj, uint8_t** result, size_t* result_len);
int from_flatty_enc_obj(const uint8_t* data, size_t data_len, EncObj* result, size_t* bytes_consumed);

int to_flatty_enc_config(const EncConfig* config, uint8_t** result, size_t* result_len);
int from_flatty_enc_config(const uint8_t* data, size_t data_len, EncConfig* result);

int to_flatty_static_config(const StaticConfig* config, uint8_t** result, size_t* result_len);
int from_flatty_static_config(const uint8_t* data, size_t data_len, StaticConfig* result, size_t* bytes_consumed);

int to_flatty_status(const Status* status, uint8_t** result, size_t* result_len);
int from_flatty_status(const uint8_t* data, size_t data_len, Status* result, size_t* bytes_consumed);

int to_flatty_callback(const Callback* callback, uint8_t** result, size_t* result_len);
int from_flatty_callback(const uint8_t* data, size_t data_len, Callback* result, size_t* bytes_consumed);

int to_flatty_task(const Task* task, uint8_t** result, size_t* result_len);
int from_flatty_task(const uint8_t* data, size_t data_len, Task* result, size_t* bytes_consumed);

int to_flatty_resp(const Resp* resp, uint8_t** result, size_t* result_len);
int from_flatty_resp(const uint8_t* data, size_t data_len, Resp* result, size_t* bytes_consumed);

#endif // SINDARIN_FLATTY_H