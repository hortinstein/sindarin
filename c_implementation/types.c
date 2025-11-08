/**
 * Implementation of type memory management functions
 */

#include "types.h"
#include <stdlib.h>
#include <string.h>

void free_enc_obj(EncObj* obj) {
    if (obj) {
        if (obj->cipherText) {
            free(obj->cipherText);
            obj->cipherText = NULL;
        }
    }
}

void free_enc_config(EncConfig* config) {
    if (config) {
        free_enc_obj(&config->encObj);
    }
}

void free_static_config(StaticConfig* config) {
    if (config) {
        if (config->buildID) free(config->buildID);
        if (config->deploymentID) free(config->deploymentID);
        if (config->callback) free(config->callback);
        memset(config, 0, sizeof(StaticConfig));
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
        memset(status, 0, sizeof(Status));
    }
}

void free_callback(Callback* callback) {
    if (callback) {
        if (callback->config) {
            free_static_config(callback->config);
            free(callback->config);
        }
        if (callback->status) {
            free_status(callback->status);
            free(callback->status);
        }
        free(callback);
    }
}

void free_task(Task* task) {
    if (task) {
        if (task->taskId) free(task->taskId);
        if (task->arg) free(task->arg);
        if (task->resp) free(task->resp);
        memset(task, 0, sizeof(Task));
    }
}

void free_resp(Resp* resp) {
    if (resp) {
        if (resp->taskId) free(resp->taskId);
        if (resp->resp) free(resp->resp);
        memset(resp, 0, sizeof(Resp));
    }
}
