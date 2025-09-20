#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "types.h"
#include "flatty.h"
#include "enkodo.h"

void test_key_serialization() {
    printf("Testing Key serialization...\n");
    
    Key key1, key2;
    
    // Generate a test key
    if (generate_key_pair(&key1, &key2) != 0) {
        printf("ERROR: Failed to generate key pair\n");
        return;
    }
    
    // Serialize key1
    uint8_t* serialized;
    size_t serialized_len;
    if (to_flatty_key(&key1, &serialized, &serialized_len) != 0) {
        printf("ERROR: Failed to serialize key\n");
        return;
    }
    
    // Deserialize back
    Key deserialized_key;
    if (from_flatty_key(serialized, serialized_len, &deserialized_key) != 0) {
        printf("ERROR: Failed to deserialize key\n");
        free(serialized);
        return;
    }
    
    // Compare
    if (memcmp(key1.data, deserialized_key.data, 32) == 0) {
        printf("✓ Key serialization test passed\n");
    } else {
        printf("✗ Key serialization test failed\n");
    }
    
    free(serialized);
}

void test_static_config_serialization() {
    printf("Testing StaticConfig serialization...\n");
    
    StaticConfig config = {0};
    config.buildID = copy_string("test_build_123");
    config.deploymentID = copy_string("test_deploy_456");
    config.killEpoch = 1234567890;
    config.interval = 60;
    config.callback = copy_string("http://127.0.0.1:8080/callback");
    
    // Generate a test public key
    Key priv_key, pub_key;
    if (generate_key_pair(&priv_key, &pub_key) != 0) {
        printf("ERROR: Failed to generate key pair for config\n");
        return;
    }
    memcpy(config.c2PubKey.data, pub_key.data, 32);
    
    // Serialize
    uint8_t* serialized;
    size_t serialized_len;
    if (to_flatty_static_config(&config, &serialized, &serialized_len) != 0) {
        printf("ERROR: Failed to serialize StaticConfig\n");
        free_static_config(&config);
        return;
    }
    
    // Deserialize
    StaticConfig deserialized_config = {0};
    size_t bytes_consumed;
    if (from_flatty_static_config(serialized, serialized_len, &deserialized_config, &bytes_consumed) != 0) {
        printf("ERROR: Failed to deserialize StaticConfig\n");
        free(serialized);
        free_static_config(&config);
        return;
    }
    
    // Compare
    int passed = 1;
    if (strcmp(config.buildID, deserialized_config.buildID) != 0) {
        printf("ERROR: buildID mismatch\n");
        passed = 0;
    }
    if (strcmp(config.deploymentID, deserialized_config.deploymentID) != 0) {
        printf("ERROR: deploymentID mismatch\n");
        passed = 0;
    }
    if (config.killEpoch != deserialized_config.killEpoch) {
        printf("ERROR: killEpoch mismatch\n");
        passed = 0;
    }
    if (config.interval != deserialized_config.interval) {
        printf("ERROR: interval mismatch\n");
        passed = 0;
    }
    if (strcmp(config.callback, deserialized_config.callback) != 0) {
        printf("ERROR: callback mismatch\n");
        passed = 0;
    }
    if (memcmp(config.c2PubKey.data, deserialized_config.c2PubKey.data, 32) != 0) {
        printf("ERROR: c2PubKey mismatch\n");
        passed = 0;
    }
    
    if (passed) {
        printf("✓ StaticConfig serialization test passed\n");
    } else {
        printf("✗ StaticConfig serialization test failed\n");
    }
    
    free(serialized);
    free_static_config(&config);
    free_static_config(&deserialized_config);
}

void test_encryption_decryption() {
    printf("Testing encryption/decryption...\n");
    
    // Generate key pairs
    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;
    
    if (generate_key_pair(&sender_priv, &sender_pub) != 0 ||
        generate_key_pair(&recipient_priv, &recipient_pub) != 0) {
        printf("ERROR: Failed to generate key pairs\n");
        return;
    }
    
    // Test message
    const char* message = "Hello, World! This is a test message.";
    size_t message_len = strlen(message);
    
    // Encrypt
    EncObj enc_obj = {0};
    if (enc(&sender_priv, &recipient_pub, (uint8_t*)message, message_len, &enc_obj) != 0) {
        printf("ERROR: Failed to encrypt message\n");
        return;
    }
    
    // Decrypt
    uint8_t* decrypted;
    size_t decrypted_len;
    if (dec(&recipient_priv, &enc_obj, &decrypted, &decrypted_len) != 0) {
        printf("ERROR: Failed to decrypt message\n");
        free_enc_obj(&enc_obj);
        return;
    }
    
    // Compare
    if (decrypted_len == message_len && memcmp(message, decrypted, message_len) == 0) {
        printf("✓ Encryption/decryption test passed\n");
    } else {
        printf("✗ Encryption/decryption test failed\n");
        printf("Original: %.*s\n", (int)message_len, message);
        printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);
    }
    
    free(decrypted);
    free_enc_obj(&enc_obj);
}

void test_enc_config_serialization() {
    printf("Testing EncConfig serialization...\n");
    
    // Create a test StaticConfig
    StaticConfig static_config = {0};
    static_config.buildID = copy_string("enc_test_build");
    static_config.deploymentID = copy_string("enc_test_deploy");
    static_config.killEpoch = 9999999;
    static_config.interval = 30;
    static_config.callback = copy_string("http://test.example.com/callback");
    
    // Generate keys
    Key priv_key, pub_key;
    if (generate_key_pair(&priv_key, &pub_key) != 0) {
        printf("ERROR: Failed to generate key pair\n");
        free_static_config(&static_config);
        return;
    }
    memcpy(static_config.c2PubKey.data, pub_key.data, 32);
    
    // Serialize the StaticConfig
    uint8_t* config_data;
    size_t config_len;
    if (to_flatty_static_config(&static_config, &config_data, &config_len) != 0) {
        printf("ERROR: Failed to serialize StaticConfig for encryption\n");
        free_static_config(&static_config);
        return;
    }
    
    // Encrypt the serialized config
    EncObj enc_obj = {0};
    if (enc(&priv_key, &pub_key, config_data, config_len, &enc_obj) != 0) {
        printf("ERROR: Failed to encrypt config\n");
        free(config_data);
        free_static_config(&static_config);
        return;
    }
    
    // Create EncConfig
    EncConfig enc_config = {0};
    memcpy(enc_config.privKey.data, priv_key.data, 32);
    memcpy(enc_config.pubKey.data, pub_key.data, 32);
    enc_config.encObj = enc_obj;
    
    // Serialize EncConfig
    uint8_t* enc_config_data;
    size_t enc_config_len;
    if (to_flatty_enc_config(&enc_config, &enc_config_data, &enc_config_len) != 0) {
        printf("ERROR: Failed to serialize EncConfig\n");
        free(config_data);
        free_static_config(&static_config);
        free_enc_obj(&enc_obj);
        return;
    }
    
    // Deserialize EncConfig
    EncConfig deserialized_enc_config = {0};
    if (from_flatty_enc_config(enc_config_data, enc_config_len, &deserialized_enc_config) != 0) {
        printf("ERROR: Failed to deserialize EncConfig\n");
        free(config_data);
        free(enc_config_data);
        free_static_config(&static_config);
        free_enc_obj(&enc_obj);
        return;
    }
    
    // Verify keys match
    if (memcmp(enc_config.privKey.data, deserialized_enc_config.privKey.data, 32) != 0 ||
        memcmp(enc_config.pubKey.data, deserialized_enc_config.pubKey.data, 32) != 0) {
        printf("ERROR: EncConfig keys don't match after serialization\n");
        free(config_data);
        free(enc_config_data);
        free_static_config(&static_config);
        free_enc_obj(&enc_obj);
        free_enc_obj(&deserialized_enc_config.encObj);
        return;
    }
    
    // Try to decrypt the config from deserialized EncConfig
    uint8_t* decrypted_config;
    size_t decrypted_len;
    if (dec(&deserialized_enc_config.privKey, &deserialized_enc_config.encObj, 
            &decrypted_config, &decrypted_len) != 0) {
        printf("ERROR: Failed to decrypt config from deserialized EncConfig\n");
        free(config_data);
        free(enc_config_data);
        free_static_config(&static_config);
        free_enc_obj(&enc_obj);
        free_enc_obj(&deserialized_enc_config.encObj);
        return;
    }
    
    // Compare decrypted config with original
    if (decrypted_len == config_len && memcmp(config_data, decrypted_config, config_len) == 0) {
        printf("✓ EncConfig serialization test passed\n");
    } else {
        printf("✗ EncConfig serialization test failed\n");
        printf("Original config length: %zu, decrypted length: %zu\n", config_len, decrypted_len);
    }
    
    free(config_data);
    free(enc_config_data);
    free(decrypted_config);
    free_static_config(&static_config);
    free_enc_obj(&enc_obj);
    free_enc_obj(&deserialized_enc_config.encObj);
}

void print_hex(const uint8_t* data, size_t len, const char* label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("... (truncated)");
    }
    printf("\n");
}

int main() {
    printf("=== C Sindarin Interoperability Tests ===\n\n");
    
    test_key_serialization();
    printf("\n");
    
    test_static_config_serialization();
    printf("\n");
    
    test_encryption_decryption();
    printf("\n");
    
    test_enc_config_serialization();
    printf("\n");
    
    printf("=== Tests Complete ===\n");
    return 0;
}