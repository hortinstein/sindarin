#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "flatty.h"
#include "enkodo.h"

int write_file_content(const char* filename, const char* content) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    fputs(content, file);
    fclose(file);
    return 0;
}

void pad_url(char** url, size_t url_max_len) {
    if (!url || !*url) return;
    
    size_t current_len = strlen(*url);
    if (current_len >= url_max_len) {
        (*url)[url_max_len - 1] = '\0';
        return;
    }
    
    char* padded = malloc(url_max_len + 1);
    if (!padded) return;
    
    strcpy(padded, *url);
    
    // Pad with null bytes
    for (size_t i = current_len; i < url_max_len; i++) {
        padded[i] = '\0';
    }
    padded[url_max_len] = '\0';
    
    free(*url);
    *url = padded;
}

int main() {
    printf("=== C Config Generator ===\n");
    
    // Create a StaticConfig similar to what Nim creates
    StaticConfig config = {0};
    config.buildID = copy_string("c_test_build_123");
    config.deploymentID = copy_string("c_deploy_456");
    config.killEpoch = 1234567890;
    config.interval = 60;
    config.callback = copy_string("http://127.0.0.1:8080/c_callback");
    
    // Pad the callback URL to 256 bytes (same as Nim does)
    pad_url(&config.callback, 256);
    
    // Generate a test public key for c2PubKey
    Key temp_priv, temp_pub;
    if (generate_key_pair(&temp_priv, &temp_pub) != 0) {
        printf("ERROR: Failed to generate c2 key pair\n");
        return 1;
    }
    memcpy(config.c2PubKey.data, temp_pub.data, 32);
    
    // Serialize the config to bytes
    uint8_t* config_data;
    size_t config_len;
    if (to_flatty_static_config(&config, &config_data, &config_len) != 0) {
        printf("ERROR: Failed to serialize StaticConfig\n");
        free_static_config(&config);
        return 1;
    }
    
    printf("Serialized StaticConfig: %zu bytes\n", config_len);
    
    // Create key pair and encrypt the config
    Key priv_key, pub_key;
    if (generate_key_pair(&priv_key, &pub_key) != 0) {
        printf("ERROR: Failed to generate encryption key pair\n");
        free(config_data);
        free_static_config(&config);
        return 1;
    }
    
    EncObj enc_obj = {0};
    if (enc(&priv_key, &pub_key, config_data, config_len, &enc_obj) != 0) {
        printf("ERROR: Failed to encrypt config\n");
        free(config_data);
        free_static_config(&config);
        return 1;
    }
    
    printf("Encrypted config: cipher length = %lld\n", (long long)enc_obj.cipherLen);
    
    // Create EncConfig
    EncConfig enc_config = {0};
    memcpy(enc_config.privKey.data, priv_key.data, 32);
    memcpy(enc_config.pubKey.data, pub_key.data, 32);
    enc_config.encObj = enc_obj;
    
    // Serialize the EncConfig
    uint8_t* enc_config_data;
    size_t enc_config_len;
    if (to_flatty_enc_config(&enc_config, &enc_config_data, &enc_config_len) != 0) {
        printf("ERROR: Failed to serialize EncConfig\n");
        free(config_data);
        free_static_config(&config);
        free_enc_obj(&enc_obj);
        return 1;
    }
    
    printf("Serialized EncConfig: %zu bytes\n", enc_config_len);
    
    // Encode to base64 (same format as Nim debug.config)
    char* b64_data;
    if (b64_encode(enc_config_data, enc_config_len, &b64_data) != 0) {
        printf("ERROR: Failed to encode to base64\n");
        free(config_data);
        free(enc_config_data);
        free_static_config(&config);
        free_enc_obj(&enc_obj);
        return 1;
    }
    
    printf("Base64 encoded: %zu characters\n", strlen(b64_data));
    
    // Write to file
    const char* output_path = "../c_generated.config";
    if (write_file_content(output_path, b64_data) != 0) {
        printf("ERROR: Failed to write config file\n");
        free(config_data);
        free(enc_config_data);
        free(b64_data);
        free_static_config(&config);
        free_enc_obj(&enc_obj);
        return 1;
    }
    
    printf("Created C-generated config at: %s\n", output_path);
    
    // Print debug info
    printf("\n--- Debug Information ---\n");
    printf("Private key (first 10 bytes): [");
    for (int i = 0; i < 10; i++) {
        printf("%d", priv_key.data[i]);
        if (i < 9) printf(", ");
    }
    printf("]\n");
    
    printf("Public key (first 10 bytes): [");
    for (int i = 0; i < 10; i++) {
        printf("%d", pub_key.data[i]);
        if (i < 9) printf(", ");
    }
    printf("]\n");
    
    printf("Cipher length: %lld\n", (long long)enc_obj.cipherLen);
    
    // Verify we can read it back
    printf("\n--- Verification Test ---\n");
    
    // Read back and decode
    uint8_t* read_binary;
    size_t read_len;
    if (b64_decode(b64_data, &read_binary, &read_len) != 0) {
        printf("ERROR: Failed to decode our own base64\n");
    } else {
        printf("Successfully decoded %zu bytes\n", read_len);
        
        // Deserialize EncConfig
        EncConfig read_enc_config = {0};
        if (from_flatty_enc_config(read_binary, read_len, &read_enc_config) == 0) {
            printf("Successfully deserialized EncConfig\n");
            
            // Try to decrypt
            uint8_t* decrypted_bytes;
            size_t decrypted_len;
            if (dec(&read_enc_config.privKey, &read_enc_config.encObj, 
                    &decrypted_bytes, &decrypted_len) == 0) {
                printf("Successfully decrypted %zu bytes\n", decrypted_len);
                
                // Try to deserialize StaticConfig
                StaticConfig decrypted_config = {0};
                size_t bytes_consumed;
                if (from_flatty_static_config(decrypted_bytes, decrypted_len, 
                                             &decrypted_config, &bytes_consumed) == 0) {
                    printf("Successfully deserialized StaticConfig!\n");
                    printf("Build ID: %s\n", decrypted_config.buildID);
                    printf("Deployment ID: %s\n", decrypted_config.deploymentID);
                    printf("Kill Epoch: %d\n", decrypted_config.killEpoch);
                    printf("Interval: %d\n", decrypted_config.interval);
                    printf("Callback (first 30 chars): %.30s\n", decrypted_config.callback);
                    
                    free_static_config(&decrypted_config);
                    printf("\nC config generation and verification PASSED!\n");
                } else {
                    printf("ERROR: Failed to deserialize decrypted StaticConfig\n");
                }
                
                free(decrypted_bytes);
            } else {
                printf("ERROR: Failed to decrypt our own config\n");
            }
            
            free_enc_obj(&read_enc_config.encObj);
        } else {
            printf("ERROR: Failed to deserialize our own EncConfig\n");
        }
        
        free(read_binary);
    }
    
    // Cleanup
    free(config_data);
    free(enc_config_data);
    free(b64_data);
    free_static_config(&config);
    free_enc_obj(&enc_obj);
    
    return 0;
}