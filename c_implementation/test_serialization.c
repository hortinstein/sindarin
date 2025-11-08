/**
 * Test serialization/deserialization functionality
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "flatty.h"
#include "types.h"

void test_key_serialization() {
    printf("Testing Key serialization...\n");

    Key key1, key2;
    for (int i = 0; i < KEY_SIZE; i++) {
        key1.data[i] = (uint8_t)i;
    }

    uint8_t buffer[KEY_SIZE];
    size_t size = serialize_key(&key1, buffer);
    assert(size == KEY_SIZE);

    size_t read_size = deserialize_key(buffer, KEY_SIZE, &key2);
    assert(read_size == KEY_SIZE);
    assert(memcmp(key1.data, key2.data, KEY_SIZE) == 0);

    printf("  ✓ Key serialization successful\n");
}

void test_static_config_serialization() {
    printf("Testing StaticConfig serialization...\n");

    StaticConfig config1 = {
        .buildID = "test-build-id",
        .deploymentID = "test-deployment",
        .killEpoch = 12345,
        .interval = 60,
        .callback = "http://example.com/callback"
    };

    // Initialize c2PubKey
    for (int i = 0; i < KEY_SIZE; i++) {
        config1.c2PubKey.data[i] = (uint8_t)(i * 2);
    }

    // Calculate buffer size and allocate
    size_t buffer_size = calc_static_config_size(&config1);
    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    assert(buffer != NULL);

    // Serialize
    size_t size = serialize_static_config(&config1, buffer);
    assert(size > 0);

    // Deserialize
    StaticConfig config2;
    memset(&config2, 0, sizeof(StaticConfig));
    size_t read_size = deserialize_static_config(buffer, size, &config2);
    assert(read_size > 0);

    // Verify
    assert(strcmp(config1.buildID, config2.buildID) == 0);
    assert(strcmp(config1.deploymentID, config2.deploymentID) == 0);
    assert(memcmp(config1.c2PubKey.data, config2.c2PubKey.data, KEY_SIZE) == 0);
    assert(config1.killEpoch == config2.killEpoch);
    assert(config1.interval == config2.interval);
    assert(strcmp(config1.callback, config2.callback) == 0);

    printf("  ✓ StaticConfig serialization successful\n");

    free(buffer);
    free_static_config(&config2);
}

void test_status_serialization() {
    printf("Testing Status serialization...\n");

    Status status1 = {
        .ip = "192.168.1.100",
        .externalIP = "203.0.113.42",
        .hostname = "test-host",
        .os = "Linux",
        .arch = "x86_64",
        .users = "root,user1",
        .bootTime = 1234567890
    };

    // Calculate buffer size and allocate
    size_t buffer_size = calc_status_size(&status1);
    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    assert(buffer != NULL);

    // Serialize
    size_t size = serialize_status(&status1, buffer);
    assert(size > 0);

    // Deserialize
    Status status2;
    memset(&status2, 0, sizeof(Status));
    size_t read_size = deserialize_status(buffer, size, &status2);
    assert(read_size > 0);

    // Verify
    assert(strcmp(status1.ip, status2.ip) == 0);
    assert(strcmp(status1.externalIP, status2.externalIP) == 0);
    assert(strcmp(status1.hostname, status2.hostname) == 0);
    assert(strcmp(status1.os, status2.os) == 0);
    assert(strcmp(status1.arch, status2.arch) == 0);
    assert(strcmp(status1.users, status2.users) == 0);
    assert(status1.bootTime == status2.bootTime);

    printf("  ✓ Status serialization successful\n");

    free(buffer);
    free_status(&status2);
}

void test_task_serialization() {
    printf("Testing Task serialization...\n");

    Task task1 = {
        .taskId = "task-12345",
        .taskNum = 42,
        .retrieved = true,
        .complete = false,
        .arg = "ls -la",
        .resp = ""
    };

    // Calculate buffer size and allocate
    size_t buffer_size = calc_task_size(&task1);
    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    assert(buffer != NULL);

    // Serialize
    size_t size = serialize_task(&task1, buffer);
    assert(size > 0);

    // Deserialize
    Task task2;
    memset(&task2, 0, sizeof(Task));
    size_t read_size = deserialize_task(buffer, size, &task2);
    assert(read_size > 0);

    // Verify
    assert(strcmp(task1.taskId, task2.taskId) == 0);
    assert(task1.taskNum == task2.taskNum);
    assert(task1.retrieved == task2.retrieved);
    assert(task1.complete == task2.complete);
    assert(strcmp(task1.arg, task2.arg) == 0);
    assert(strcmp(task1.resp, task2.resp) == 0);

    printf("  ✓ Task serialization successful\n");

    free(buffer);
    free_task(&task2);
}

void test_enc_obj_serialization() {
    printf("Testing EncObj serialization...\n");

    // Create a test EncObj
    EncObj obj1;
    for (int i = 0; i < KEY_SIZE; i++) obj1.publicKey.data[i] = (uint8_t)i;
    for (int i = 0; i < NONCE_SIZE; i++) obj1.nonce.data[i] = (uint8_t)(i + 32);
    for (int i = 0; i < MAC_SIZE; i++) obj1.mac.data[i] = (uint8_t)(i + 56);

    const char* test_cipher = "This is encrypted data";
    obj1.cipherLen = strlen(test_cipher);
    obj1.cipherText = (uint8_t*)malloc(obj1.cipherLen);
    memcpy(obj1.cipherText, test_cipher, obj1.cipherLen);

    // Calculate buffer size and allocate
    size_t buffer_size = calc_enc_obj_size(&obj1);
    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    assert(buffer != NULL);

    // Serialize
    size_t size = serialize_enc_obj(&obj1, buffer);
    assert(size > 0);

    // Deserialize
    EncObj obj2;
    memset(&obj2, 0, sizeof(EncObj));
    size_t read_size = deserialize_enc_obj(buffer, size, &obj2);
    assert(read_size > 0);

    // Verify
    assert(memcmp(obj1.publicKey.data, obj2.publicKey.data, KEY_SIZE) == 0);
    assert(memcmp(obj1.nonce.data, obj2.nonce.data, NONCE_SIZE) == 0);
    assert(memcmp(obj1.mac.data, obj2.mac.data, MAC_SIZE) == 0);
    assert(obj1.cipherLen == obj2.cipherLen);
    assert(memcmp(obj1.cipherText, obj2.cipherText, obj1.cipherLen) == 0);

    printf("  ✓ EncObj serialization successful\n");

    free(buffer);
    free_enc_obj(&obj1);
    free_enc_obj(&obj2);
}

int main() {
    printf("=== C Serialization Tests ===\n\n");

    test_key_serialization();
    test_static_config_serialization();
    test_status_serialization();
    test_task_serialization();
    test_enc_obj_serialization();

    printf("\n=== All tests passed! ===\n");

    return 0;
}
