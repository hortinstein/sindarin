/**
 * Test C to Python interoperability
 * This program creates encrypted and serialized data in C that Python should be able to read
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "enkodo.h"
#include "flatty.h"
#include "types.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== C to Python Interoperability Test ===\n\n");

    // Generate key pairs
    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;

    printf("1. Generating key pairs...\n");
    generate_key_pair(&sender_priv, &sender_pub);
    generate_key_pair(&recipient_priv, &recipient_pub);

    print_hex("Sender Private Key", sender_priv.data, KEY_SIZE);
    print_hex("Sender Public Key", sender_pub.data, KEY_SIZE);
    print_hex("Recipient Private Key", recipient_priv.data, KEY_SIZE);
    print_hex("Recipient Public Key", recipient_pub.data, KEY_SIZE);

    // Save keys to files for Python
    write_bytes_to_file("c_sender_private.key", sender_priv.data, KEY_SIZE);
    write_bytes_to_file("c_sender_public.key", sender_pub.data, KEY_SIZE);
    write_bytes_to_file("c_recipient_private.key", recipient_priv.data, KEY_SIZE);
    write_bytes_to_file("c_recipient_public.key", recipient_pub.data, KEY_SIZE);
    printf("  ✓ Keys saved to files\n\n");

    // Test 1: Encrypt a simple message
    printf("2. Encrypting a simple message...\n");
    const char* message = "Hello from C! This is a test message.";
    printf("  Original message: %s\n", message);

    EncObj enc_obj;
    memset(&enc_obj, 0, sizeof(EncObj));
    int result = enc(&sender_priv, &recipient_pub,
                    (const uint8_t*)message, strlen(message), &enc_obj);
    if (result != 0) {
        fprintf(stderr, "Encryption failed!\n");
        return 1;
    }

    // Serialize EncObj
    size_t enc_obj_size = calc_enc_obj_size(&enc_obj);
    uint8_t* enc_buffer = (uint8_t*)malloc(enc_obj_size);
    serialize_enc_obj(&enc_obj, enc_buffer);

    // Save encrypted data
    write_bytes_to_file("c_encrypted.bin", enc_buffer, enc_obj_size);
    printf("  ✓ Encrypted message saved to c_encrypted.bin\n");
    printf("  Message length: %zu bytes\n", strlen(message));
    printf("  Encrypted size: %zu bytes\n\n", enc_obj_size);

    free(enc_buffer);

    // Test 2: Create a StaticConfig
    printf("3. Creating StaticConfig...\n");
    StaticConfig config = {
        .buildID = "c-build-123",
        .deploymentID = "c-deploy-456",
        .killEpoch = 1234567890,
        .interval = 300,
        .callback = "https://c2.example.com/callback"
    };
    memcpy(config.c2PubKey.data, recipient_pub.data, KEY_SIZE);

    size_t config_size = calc_static_config_size(&config);
    uint8_t* config_buffer = (uint8_t*)malloc(config_size);
    serialize_static_config(&config, config_buffer);

    write_bytes_to_file("c_static_config.bin", config_buffer, config_size);
    printf("  ✓ StaticConfig saved to c_static_config.bin\n");
    printf("  Build ID: %s\n", config.buildID);
    printf("  Deployment ID: %s\n", config.deploymentID);
    printf("  Kill Epoch: %d\n", config.killEpoch);
    printf("  Interval: %d\n", config.interval);
    printf("  Callback: %s\n\n", config.callback);

    free(config_buffer);

    // Test 3: Create an EncConfig (encrypted configuration)
    printf("4. Creating EncConfig...\n");

    // First serialize the StaticConfig as the message to encrypt
    size_t plain_config_size = calc_static_config_size(&config);
    uint8_t* plain_config_buffer = (uint8_t*)malloc(plain_config_size);
    size_t plain_size = serialize_static_config(&config, plain_config_buffer);

    // Create EncConfig
    EncConfig enc_config;
    memcpy(enc_config.privKey.data, sender_priv.data, KEY_SIZE);
    memcpy(enc_config.pubKey.data, sender_pub.data, KEY_SIZE);

    memset(&enc_config.encObj, 0, sizeof(EncObj));
    enc(&enc_config.privKey, &enc_config.pubKey,
        plain_config_buffer, plain_size, &enc_config.encObj);

    // Serialize EncConfig
    size_t enc_config_size = calc_enc_config_size(&enc_config);
    uint8_t* enc_config_buffer = (uint8_t*)malloc(enc_config_size);
    serialize_enc_config(&enc_config, enc_config_buffer);

    write_bytes_to_file("c_enc_config.bin", enc_config_buffer, enc_config_size);
    printf("  ✓ EncConfig saved to c_enc_config.bin\n");
    printf("  EncConfig size: %zu bytes\n\n", enc_config_size);

    free(plain_config_buffer);
    free(enc_config_buffer);

    // Test 4: Create a Task
    printf("5. Creating Task...\n");
    Task task = {
        .taskId = "c-task-001",
        .taskNum = 42,
        .retrieved = true,
        .complete = false,
        .arg = "whoami",
        .resp = "root"
    };

    size_t task_size = calc_task_size(&task);
    uint8_t* task_buffer = (uint8_t*)malloc(task_size);
    serialize_task(&task, task_buffer);

    write_bytes_to_file("c_task.bin", task_buffer, task_size);
    printf("  ✓ Task saved to c_task.bin\n");
    printf("  Task ID: %s\n", task.taskId);
    printf("  Task Num: %ld\n", task.taskNum);
    printf("  Retrieved: %s\n", task.retrieved ? "true" : "false");
    printf("  Complete: %s\n", task.complete ? "true" : "false");
    printf("  Arg: %s\n", task.arg);
    printf("  Resp: %s\n\n", task.resp);

    free(task_buffer);

    // Test 5: Create a Status
    printf("6. Creating Status...\n");
    Status status = {
        .ip = "10.0.0.42",
        .externalIP = "203.0.113.42",
        .hostname = "c-test-host",
        .os = "Linux",
        .arch = "x86_64",
        .users = "root,admin,user1",
        .bootTime = 1234567890
    };

    size_t status_size = calc_status_size(&status);
    uint8_t* status_buffer = (uint8_t*)malloc(status_size);
    serialize_status(&status, status_buffer);

    write_bytes_to_file("c_status.bin", status_buffer, status_size);
    printf("  ✓ Status saved to c_status.bin\n");
    printf("  IP: %s\n", status.ip);
    printf("  External IP: %s\n", status.externalIP);
    printf("  Hostname: %s\n", status.hostname);
    printf("  OS: %s\n", status.os);
    printf("  Arch: %s\n", status.arch);
    printf("  Users: %s\n", status.users);
    printf("  Boot Time: %ld\n\n", status.bootTime);

    free(status_buffer);

    // Cleanup
    free_enc_obj(&enc_obj);
    free_enc_obj(&enc_config.encObj);

    printf("=== All C data files created successfully! ===\n");
    printf("Python can now read these files:\n");
    printf("  - c_encrypted.bin (EncObj)\n");
    printf("  - c_static_config.bin (StaticConfig)\n");
    printf("  - c_enc_config.bin (EncConfig)\n");
    printf("  - c_task.bin (Task)\n");
    printf("  - c_status.bin (Status)\n");
    printf("  - c_*_*.key (Keys for decryption)\n");

    return 0;
}
