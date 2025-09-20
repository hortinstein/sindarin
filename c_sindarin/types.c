#include "types.h"
#include <stdlib.h>
#include <string.h>

// Include the copy_string declaration here so test files can use it
char* copy_string(const char* src);

void free_enc_obj(EncObj* obj) {
    if (obj && obj->cipherText) {
        free(obj->cipherText);
        obj->cipherText = NULL;
        obj->cipherLen = 0;
    }
}

void free_enc_config(EncConfig* config) {
    if (config) {
        free_enc_obj(&config->encObj);
    }
}

void free_static_config(StaticConfig* config) {
    if (config) {
        if (config->buildID) {
            free(config->buildID);
            config->buildID = NULL;
        }
        if (config->deploymentID) {
            free(config->deploymentID);
            config->deploymentID = NULL;
        }
        if (config->callback) {
            free(config->callback);
            config->callback = NULL;
        }
    }
}

void free_status(Status* status) {
    if (status) {
        if (status->ip) free(status->ip);
        if (status->externalIP) free(status->externalIP);
        if (status->hostname) free(status->hostname);
        if (status->os) free(status->os);
        if (status->arch) free(status->arch);
        if (status->users) free(status->users);
        
        status->ip = NULL;
        status->externalIP = NULL;
        status->hostname = NULL;
        status->os = NULL;
        status->arch = NULL;
        status->users = NULL;
    }
}

void free_callback(Callback* callback) {
    if (callback) {
        if (callback->config) {
            free_static_config(callback->config);
            free(callback->config);
            callback->config = NULL;
        }
        if (callback->status) {
            free_status(callback->status);
            free(callback->status);
            callback->status = NULL;
        }
    }
}

void free_task(Task* task) {
    if (task) {
        if (task->taskId) free(task->taskId);
        if (task->arg) free(task->arg);
        if (task->resp) free(task->resp);
        
        task->taskId = NULL;
        task->arg = NULL;
        task->resp = NULL;
    }
}

void free_resp(Resp* resp) {
    if (resp) {
        if (resp->taskId) free(resp->taskId);
        if (resp->resp) free(resp->resp);
        
        resp->taskId = NULL;
        resp->resp = NULL;
    }
}

// Helper functions for copying strings
char* copy_string(const char* src) {
    if (!src) return NULL;
    size_t len = strlen(src);
    char* dest = malloc(len + 1);
    if (dest) {
        strcpy(dest, src);
    }
    return dest;
}

// Helper function to copy key data
void copy_key(Key* dest, const Key* src) {
    if (dest && src) {
        memcpy(dest->data, src->data, 32);
    }
}

void copy_nonce(Nonce* dest, const Nonce* src) {
    if (dest && src) {
        memcpy(dest->data, src->data, 24);
    }
}

void copy_mac(Mac* dest, const Mac* src) {
    if (dest && src) {
        memcpy(dest->data, src->data, 16);
    }
}