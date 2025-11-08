/**
 * Test Python to C interoperability
 * This program reads encrypted and serialized data created by Python
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "enkodo.h"
#include "flatty.h"
#include "types.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int main() {
    printf("=== Python to C Interoperability Test ===\n\n");

    // Test 1: Read encrypted message from Python
    printf("1. Reading encrypted message from Python...\n");

    size_t enc_size;
    uint8_t* enc_buffer = read_bytes_from_file("python_encrypted.bin", &enc_size);
    if (!enc_buffer) {
        printf("  ⚠ python_encrypted.bin not found - run Python test first\n\n");
    } else {
        printf("  File size: %zu bytes\n", enc_size);

        // Deserialize EncObj
        EncObj enc_obj;
        memset(&enc_obj, 0, sizeof(EncObj));
        size_t read_size = deserialize_enc_obj(enc_buffer, enc_size, &enc_obj);
        if (read_size == 0) {
            printf("  ✗ Failed to deserialize EncObj\n\n");
        } else {
            printf("  ✓ EncObj deserialized successfully\n");
            printf("  Cipher length: %ld bytes\n", enc_obj.cipherLen);

            // Try to decrypt with recipient's private key
            size_t key_size;
            uint8_t* recipient_priv_data = read_bytes_from_file("python_recipient_private.key", &key_size);
            if (recipient_priv_data && key_size == KEY_SIZE) {
                Key recipient_priv;
                memcpy(recipient_priv.data, recipient_priv_data, KEY_SIZE);

                uint8_t* plaintext = NULL;
                size_t plaintext_len = 0;
                int result = dec(&recipient_priv, &enc_obj, &plaintext, &plaintext_len);

                if (result == 0) {
                    printf("  ✓ Message decrypted successfully\n");
                    printf("  Decrypted message: %.*s\n\n", (int)plaintext_len, plaintext);
                    free(plaintext);
                } else {
                    printf("  ✗ Decryption failed\n\n");
                }

                free(recipient_priv_data);
            } else {
                printf("  ⚠ Could not read recipient private key\n\n");
            }

            free_enc_obj(&enc_obj);
        }

        free(enc_buffer);
    }

    // Test 2: Read StaticConfig from Python
    printf("2. Reading StaticConfig from Python...\n");

    size_t config_size;
    uint8_t* config_buffer = read_bytes_from_file("python_static_config.bin", &config_size);
    if (!config_buffer) {
        printf("  ⚠ python_static_config.bin not found - run Python test first\n\n");
    } else {
        printf("  File size: %zu bytes\n", config_size);

        StaticConfig config;
        memset(&config, 0, sizeof(StaticConfig));
        size_t read_size = deserialize_static_config(config_buffer, config_size, &config);

        if (read_size == 0) {
            printf("  ✗ Failed to deserialize StaticConfig\n\n");
        } else {
            printf("  ✓ StaticConfig deserialized successfully\n");
            printf("  Build ID: %s\n", config.buildID);
            printf("  Deployment ID: %s\n", config.deploymentID);
            printf("  Kill Epoch: %d\n", config.killEpoch);
            printf("  Interval: %d\n", config.interval);
            printf("  Callback: %s\n\n", config.callback);

            free_static_config(&config);
        }

        free(config_buffer);
    }

    // Test 3: Read EncConfig from Python
    printf("3. Reading EncConfig from Python...\n");

    size_t enc_config_size;
    uint8_t* enc_config_buffer = read_bytes_from_file("python_enc_config.bin", &enc_config_size);
    if (!enc_config_buffer) {
        printf("  ⚠ python_enc_config.bin not found - run Python test first\n\n");
    } else {
        printf("  File size: %zu bytes\n", enc_config_size);

        EncConfig enc_config;
        memset(&enc_config, 0, sizeof(EncConfig));
        size_t read_size = deserialize_enc_config(enc_config_buffer, enc_config_size, &enc_config);

        if (read_size == 0) {
            printf("  ✗ Failed to deserialize EncConfig\n\n");
        } else {
            printf("  ✓ EncConfig deserialized successfully\n");
            print_hex("  Private Key", enc_config.privKey.data, KEY_SIZE);
            print_hex("  Public Key", enc_config.pubKey.data, KEY_SIZE);
            printf("  Encrypted object cipher length: %ld bytes\n", enc_config.encObj.cipherLen);

            // Try to decrypt the embedded config
            uint8_t* plaintext = NULL;
            size_t plaintext_len = 0;
            int result = dec(&enc_config.privKey, &enc_config.encObj, &plaintext, &plaintext_len);

            if (result == 0) {
                printf("  ✓ Embedded config decrypted successfully\n");

                // Try to deserialize the decrypted StaticConfig
                StaticConfig inner_config;
                memset(&inner_config, 0, sizeof(StaticConfig));
                size_t inner_read = deserialize_static_config(plaintext, plaintext_len, &inner_config);

                if (inner_read > 0) {
                    printf("  ✓ Inner StaticConfig deserialized\n");
                    printf("    Build ID: %s\n", inner_config.buildID);
                    printf("    Deployment ID: %s\n", inner_config.deploymentID);
                    printf("    Kill Epoch: %d\n", inner_config.killEpoch);
                    printf("    Interval: %d\n", inner_config.interval);
                    printf("    Callback: %s\n\n", inner_config.callback);

                    free_static_config(&inner_config);
                } else {
                    printf("  ✗ Failed to deserialize inner StaticConfig\n\n");
                }

                free(plaintext);
            } else {
                printf("  ✗ Failed to decrypt embedded config\n\n");
            }

            free_enc_obj(&enc_config.encObj);
        }

        free(enc_config_buffer);
    }

    // Test 4: Read Task from Python
    printf("4. Reading Task from Python...\n");

    size_t task_size;
    uint8_t* task_buffer = read_bytes_from_file("python_task.bin", &task_size);
    if (!task_buffer) {
        printf("  ⚠ python_task.bin not found - run Python test first\n\n");
    } else {
        printf("  File size: %zu bytes\n", task_size);

        Task task;
        memset(&task, 0, sizeof(Task));
        size_t read_size = deserialize_task(task_buffer, task_size, &task);

        if (read_size == 0) {
            printf("  ✗ Failed to deserialize Task\n\n");
        } else {
            printf("  ✓ Task deserialized successfully\n");
            printf("  Task ID: %s\n", task.taskId);
            printf("  Task Num: %ld\n", task.taskNum);
            printf("  Retrieved: %s\n", task.retrieved ? "true" : "false");
            printf("  Complete: %s\n", task.complete ? "true" : "false");
            printf("  Arg: %s\n", task.arg);
            printf("  Resp: %s\n\n", task.resp);

            free_task(&task);
        }

        free(task_buffer);
    }

    // Test 5: Read Status from Python
    printf("5. Reading Status from Python...\n");

    size_t status_size;
    uint8_t* status_buffer = read_bytes_from_file("python_status.bin", &status_size);
    if (!status_buffer) {
        printf("  ⚠ python_status.bin not found - run Python test first\n\n");
    } else {
        printf("  File size: %zu bytes\n", status_size);

        Status status;
        memset(&status, 0, sizeof(Status));
        size_t read_size = deserialize_status(status_buffer, status_size, &status);

        if (read_size == 0) {
            printf("  ✗ Failed to deserialize Status\n\n");
        } else {
            printf("  ✓ Status deserialized successfully\n");
            printf("  IP: %s\n", status.ip);
            printf("  External IP: %s\n", status.externalIP);
            printf("  Hostname: %s\n", status.hostname);
            printf("  OS: %s\n", status.os);
            printf("  Arch: %s\n", status.arch);
            printf("  Users: %s\n", status.users);
            printf("  Boot Time: %ld\n\n", status.bootTime);

            free_status(&status);
        }

        free(status_buffer);
    }

    printf("=== Python to C interoperability test complete! ===\n");

    return 0;
}
