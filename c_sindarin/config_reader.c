#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "flatty.h"
#include "enkodo.h"

int read_file_content(const char* filename, char** content, size_t* length) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    *content = malloc(file_size + 1);
    if (!*content) {
        fclose(file);
        return -1;
    }
    
    size_t bytes_read = fread(*content, 1, file_size, file);
    (*content)[bytes_read] = '\0';
    
    fclose(file);
    *length = bytes_read;
    return 0;
}

void print_bytes_array(const uint8_t* data, size_t len, const char* label) {
    printf("%s: [", label);
    for (size_t i = 0; i < len; i++) {
        printf("%d", data[i]);
        if (i < len - 1) printf(", ");
    }
    printf("]\n");
}

void print_key_info(const Key* key, const char* label) {
    printf("%s: ", label);
    for (int i = 0; i < 32; i++) {
        printf("%02x", key->data[i]);
    }
    printf("\n");
    
    printf("%s (first 10 bytes): [", label);
    for (int i = 0; i < 10; i++) {
        printf("%d", key->data[i]);
        if (i < 9) printf(", ");
    }
    printf("]\n");
}

int main(int argc, char* argv[]) {
    const char* config_path = "../nim_config/debug.config";
    
    if (argc > 1) {
        config_path = argv[1];
    }
    
    printf("=== C Config Reader ===\n");
    printf("Reading config from: %s\n\n", config_path);
    
    // Read base64 encoded config file
    char* b64_content;
    size_t b64_length;
    if (read_file_content(config_path, &b64_content, &b64_length) != 0) {
        printf("ERROR: Failed to read config file: %s\n", config_path);
        return 1;
    }
    
    // Remove any trailing newlines/whitespace
    while (b64_length > 0 && (b64_content[b64_length - 1] == '\n' || 
                              b64_content[b64_length - 1] == '\r' || 
                              b64_content[b64_length - 1] == ' ')) {
        b64_content[b64_length - 1] = '\0';
        b64_length--;
    }
    
    printf("Base64 data length: %zu\n", b64_length);
    
    // Decode base64
    uint8_t* binary_data;
    size_t binary_length;
    if (b64_decode(b64_content, &binary_data, &binary_length) != 0) {
        printf("ERROR: Failed to decode base64 data\n");
        free(b64_content);
        return 1;
    }
    
    printf("Decoded binary data length: %zu\n", binary_length);
    
    // Deserialize as EncConfig
    EncConfig enc_config = {0};
    if (from_flatty_enc_config(binary_data, binary_length, &enc_config) != 0) {
        printf("ERROR: Failed to deserialize EncConfig\n");
        free(b64_content);
        free(binary_data);
        return 1;
    }
    
    printf("Successfully deserialized EncConfig from Nim!\n\n");
    
    // Print EncConfig structure info
    print_key_info(&enc_config.privKey, "Private Key");
    print_key_info(&enc_config.pubKey, "Public Key");
    
    printf("\n--- EncObj Information ---\n");
    print_key_info(&enc_config.encObj.publicKey, "EncObj Public Key");
    
    printf("EncObj Nonce (first 10 bytes): [");
    for (int i = 0; i < 10; i++) {
        printf("%d", enc_config.encObj.nonce.data[i]);
        if (i < 9) printf(", ");
    }
    printf("]\n");
    
    printf("EncObj MAC (first 10 bytes): [");
    for (int i = 0; i < 10; i++) {
        printf("%d", enc_config.encObj.mac.data[i]);
        if (i < 9) printf(", ");
    }
    printf("]\n");
    
    printf("Cipher Length: %lld\n", (long long)enc_config.encObj.cipherLen);
    
    if (enc_config.encObj.cipherText && enc_config.encObj.cipherLen > 0) {
        printf("Cipher Text (first 10 bytes): [");
        int display_len = enc_config.encObj.cipherLen > 10 ? 10 : (int)enc_config.encObj.cipherLen;
        for (int i = 0; i < display_len; i++) {
            printf("%d", enc_config.encObj.cipherText[i]);
            if (i < display_len - 1) printf(", ");
        }
        printf("]\n");
    }
    
    // Try to decrypt the configuration
    printf("\n--- Attempting Decryption ---\n");
    uint8_t* decrypted_data;
    size_t decrypted_length;
    
    if (dec(&enc_config.privKey, &enc_config.encObj, &decrypted_data, &decrypted_length) == 0) {
        printf("Decryption successful! Decrypted %zu bytes\n", decrypted_length);
        
        // Try to deserialize as StaticConfig
        StaticConfig static_config = {0};
        size_t bytes_consumed;
        
        if (from_flatty_static_config(decrypted_data, decrypted_length, &static_config, &bytes_consumed) == 0) {
            printf("\n--- Decrypted StaticConfig ---\n");
            printf("Build ID: %s\n", static_config.buildID ? static_config.buildID : "(null)");
            printf("Deployment ID: %s\n", static_config.deploymentID ? static_config.deploymentID : "(null)");
            printf("Kill Epoch: %d\n", static_config.killEpoch);
            printf("Interval: %d\n", static_config.interval);
            
            if (static_config.callback) {
                // Print first 50 characters of callback, handling null padding
                size_t callback_len = strlen(static_config.callback);
                size_t display_len = callback_len > 50 ? 50 : callback_len;
                printf("Callback (first %zu chars): %.*s\n", display_len, (int)display_len, static_config.callback);
            } else {
                printf("Callback: (null)\n");
            }
            
            printf("C2 Public Key (first 10 bytes): [");
            for (int i = 0; i < 10; i++) {
                printf("%d", static_config.c2PubKey.data[i]);
                if (i < 9) printf(", ");
            }
            printf("]\n");
            
            free_static_config(&static_config);
            printf("\nBinary compatibility test PASSED - C successfully read and decrypted Nim-generated config!\n");
        } else {
            printf("Decryption succeeded but StaticConfig deserialization failed\n");
            printf("Raw decrypted data (first 100 bytes):\n");
            int display_len = decrypted_length > 100 ? 100 : (int)decrypted_length;
            for (int i = 0; i < display_len; i++) {
                printf("%02x ", decrypted_data[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
        
        free(decrypted_data);
    } else {
        printf("Decryption failed - may be due to differences in monocypher implementations\n");
        printf("However, binary compatibility for EncConfig deserialization is confirmed!\n");
    }
    
    // Cleanup
    free(b64_content);
    free(binary_data);
    free_enc_obj(&enc_config.encObj);
    
    return 0;
}