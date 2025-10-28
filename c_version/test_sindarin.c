// For strdup in C11 mode
#define _POSIX_C_SOURCE 200809L

#include "sindarin.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Helper function to print hex
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper function to compare keys
int compare_keys(const Key* k1, const Key* k2) {
    return memcmp(k1->data, k2->data, 32) == 0;
}

// Test encryption/decryption
void test_encryption() {
    printf("=== Testing Encryption/Decryption ===\n");

    // Generate key pairs
    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;

    generate_key_pair(&sender_priv, &sender_pub);
    generate_key_pair(&recipient_priv, &recipient_pub);

    print_hex("Sender Private", sender_priv.data, 32);
    print_hex("Sender Public", sender_pub.data, 32);
    print_hex("Recipient Private", recipient_priv.data, 32);
    print_hex("Recipient Public", recipient_pub.data, 32);

    // Test message
    const char* message = "Hello from C!";
    size_t msg_len = strlen(message);

    printf("Original message: %s\n", message);

    // Encrypt
    EncObj* enc_obj = encrypt_message(&sender_priv, &recipient_pub,
                                       (uint8_t*)message, msg_len);
    assert(enc_obj != NULL);

    print_hex("Nonce", enc_obj->nonce.data, 24);
    print_hex("MAC", enc_obj->mac.data, 16);
    printf("Cipher length: %ld\n", enc_obj->cipherLen);

    // Decrypt
    size_t decrypted_len;
    uint8_t* decrypted = decrypt_message(&recipient_priv, enc_obj, &decrypted_len);
    assert(decrypted != NULL);
    assert(decrypted_len == msg_len);
    assert(memcmp(decrypted, message, msg_len) == 0);

    printf("Decrypted message: %.*s\n", (int)decrypted_len, decrypted);
    printf("Encryption/Decryption: PASSED\n\n");

    free(decrypted);
    free_enc_obj(enc_obj);
}

// Test StaticConfig serialization
void test_static_config() {
    printf("=== Testing StaticConfig Serialization ===\n");

    // Create test config
    StaticConfig config;
    config.buildID = strdup("test-build-1");
    config.deploymentID = strdup("deploy-abc-123");
    config.killEpoch = 1234567890;
    config.interval = 60;
    config.callback = strdup("https://c2.example.com/callback");

    // Generate a test key
    Key c2_priv, c2_pub;
    generate_key_pair(&c2_priv, &c2_pub);
    config.c2PubKey = c2_pub;

    printf("Original config:\n");
    printf("  buildID: %s\n", config.buildID);
    printf("  deploymentID: %s\n", config.deploymentID);
    printf("  killEpoch: %d\n", config.killEpoch);
    printf("  interval: %d\n", config.interval);
    printf("  callback: %s\n", config.callback);

    // Serialize
    size_t ser_len;
    uint8_t* serialized = serialize_static_config(&config, &ser_len);
    printf("Serialized length: %zu bytes\n", ser_len);

    // Deserialize
    size_t offset = 0;
    StaticConfig* deserialized = deserialize_static_config(serialized, ser_len, &offset);
    assert(deserialized != NULL);

    printf("Deserialized config:\n");
    printf("  buildID: %s\n", deserialized->buildID);
    printf("  deploymentID: %s\n", deserialized->deploymentID);
    printf("  killEpoch: %d\n", deserialized->killEpoch);
    printf("  interval: %d\n", deserialized->interval);
    printf("  callback: %s\n", deserialized->callback);

    // Verify
    assert(strcmp(config.buildID, deserialized->buildID) == 0);
    assert(strcmp(config.deploymentID, deserialized->deploymentID) == 0);
    assert(config.killEpoch == deserialized->killEpoch);
    assert(config.interval == deserialized->interval);
    assert(strcmp(config.callback, deserialized->callback) == 0);
    assert(compare_keys(&config.c2PubKey, &deserialized->c2PubKey));

    printf("StaticConfig serialization: PASSED\n\n");

    free(serialized);
    free_static_config(deserialized);
    free(config.buildID);
    free(config.deploymentID);
    free(config.callback);
}

// Test Task serialization
void test_task() {
    printf("=== Testing Task Serialization ===\n");

    Task task;
    task.taskId = strdup("task-12345");
    task.taskNum = 42;
    task.retrieved = true;
    task.complete = false;
    task.arg = strdup("ls -la");
    task.resp = strdup("");

    printf("Original task:\n");
    printf("  taskId: %s\n", task.taskId);
    printf("  taskNum: %ld\n", task.taskNum);
    printf("  retrieved: %d\n", task.retrieved);
    printf("  complete: %d\n", task.complete);
    printf("  arg: %s\n", task.arg);

    // Serialize
    size_t ser_len;
    uint8_t* serialized = serialize_task(&task, &ser_len);
    printf("Serialized length: %zu bytes\n", ser_len);

    // Deserialize
    Task* deserialized = deserialize_task(serialized, ser_len);
    assert(deserialized != NULL);

    printf("Deserialized task:\n");
    printf("  taskId: %s\n", deserialized->taskId);
    printf("  taskNum: %ld\n", deserialized->taskNum);
    printf("  retrieved: %d\n", deserialized->retrieved);
    printf("  complete: %d\n", deserialized->complete);
    printf("  arg: %s\n", deserialized->arg);

    // Verify
    assert(strcmp(task.taskId, deserialized->taskId) == 0);
    assert(task.taskNum == deserialized->taskNum);
    assert(task.retrieved == deserialized->retrieved);
    assert(task.complete == deserialized->complete);
    assert(strcmp(task.arg, deserialized->arg) == 0);

    printf("Task serialization: PASSED\n\n");

    free(serialized);
    free_task(deserialized);
    free(task.taskId);
    free(task.arg);
    free(task.resp);
}

// Test EncConfig with encryption
void test_enc_config() {
    printf("=== Testing EncConfig with Encryption ===\n");

    // Generate key pair
    Key priv_key, pub_key;
    generate_key_pair(&priv_key, &pub_key);

    // Create a config to encrypt
    StaticConfig config;
    config.buildID = strdup("build-001");
    config.deploymentID = strdup("deploy-001");
    config.killEpoch = 9999999;
    config.interval = 30;
    config.callback = strdup("https://c2.test.local/api");

    Key c2_priv, c2_pub;
    generate_key_pair(&c2_priv, &c2_pub);
    config.c2PubKey = c2_pub;

    // Serialize the config
    size_t config_len;
    uint8_t* config_data = serialize_static_config(&config, &config_len);

    // Encrypt the serialized config
    EncObj* enc_obj = encrypt_message(&priv_key, &pub_key, config_data, config_len);
    assert(enc_obj != NULL);

    // Create EncConfig
    EncConfig enc_config;
    enc_config.privKey = priv_key;
    enc_config.pubKey = pub_key;
    enc_config.encObj = *enc_obj;

    printf("Created EncConfig with encrypted StaticConfig\n");
    print_hex("EncConfig Private Key", enc_config.privKey.data, 32);
    print_hex("EncConfig Public Key", enc_config.pubKey.data, 32);

    // Serialize EncConfig
    size_t enc_config_len;
    uint8_t* enc_config_data = serialize_enc_config(&enc_config, &enc_config_len);
    printf("Serialized EncConfig length: %zu bytes\n", enc_config_len);

    // Deserialize EncConfig
    EncConfig* deserialized_enc_config = deserialize_enc_config(enc_config_data, enc_config_len);
    assert(deserialized_enc_config != NULL);

    printf("Deserialized EncConfig\n");

    // Decrypt the config
    size_t decrypted_len;
    uint8_t* decrypted_config_data = decrypt_message(&deserialized_enc_config->privKey,
                                                      &deserialized_enc_config->encObj,
                                                      &decrypted_len);
    assert(decrypted_config_data != NULL);

    // Deserialize the decrypted config
    size_t offset = 0;
    StaticConfig* decrypted_config = deserialize_static_config(decrypted_config_data,
                                                                 decrypted_len, &offset);
    assert(decrypted_config != NULL);

    printf("Decrypted StaticConfig:\n");
    printf("  buildID: %s\n", decrypted_config->buildID);
    printf("  deploymentID: %s\n", decrypted_config->deploymentID);
    printf("  killEpoch: %d\n", decrypted_config->killEpoch);
    printf("  interval: %d\n", decrypted_config->interval);

    // Verify
    assert(strcmp(config.buildID, decrypted_config->buildID) == 0);
    assert(strcmp(config.deploymentID, decrypted_config->deploymentID) == 0);
    assert(config.killEpoch == decrypted_config->killEpoch);
    assert(config.interval == decrypted_config->interval);

    printf("EncConfig with encryption: PASSED\n\n");

    free(config_data);
    free(enc_obj);
    free(enc_config_data);
    free(decrypted_config_data);
    free_enc_config(deserialized_enc_config);
    free_static_config(decrypted_config);
    free(config.buildID);
    free(config.deploymentID);
    free(config.callback);
}

// Test reading Nim-generated debug.config
void test_nim_compatibility() {
    printf("=== Testing Nim Compatibility ===\n");

    // Try to read the debug.config file generated by Nim
    FILE* f = fopen("../nim_config/debug.config", "rb");
    if (!f) {
        printf("Note: Could not open ../nim_config/debug.config\n");
        printf("Run 'cd nim_config && nimble run' to generate it\n\n");
        return;
    }

    // Read file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    printf("Reading debug.config (%ld bytes)\n", file_size);

    // Read base64 encoded data
    char* b64_data = (char*)malloc(file_size + 1);
    fread(b64_data, 1, file_size, f);
    b64_data[file_size] = '\0';
    fclose(f);

    // TODO: Implement base64 decoding and test deserialization
    printf("Note: Full Nim compatibility test requires base64 decoding\n");
    printf("The serialization format should be compatible with Nim's Flatty\n\n");

    free(b64_data);
}

int main() {
    printf("Sindarin C Implementation Tests\n");
    printf("================================\n\n");

    test_encryption();
    test_static_config();
    test_task();
    test_enc_config();
    test_nim_compatibility();

    printf("All tests completed!\n");
    return 0;
}
