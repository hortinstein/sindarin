// For strdup in C11 mode
#define _POSIX_C_SOURCE 200809L

#include "sindarin.h"
#include <stdio.h>
#include <string.h>

// Helper function to print hex
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int main() {
    printf("======================================================================\n");
    printf("Testing C Reading Python-Generated Config\n");
    printf("======================================================================\n");

    // Try to read the Python-generated config file
    FILE* f = fopen("../python_generated.config", "rb");
    if (!f) {
        printf("ERROR: Could not open ../python_generated.config\n");
        printf("Run 'python3 generate_python_config.py' to generate it\n");
        return 1;
    }

    // Read file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    printf("\nReading python_generated.config (%ld bytes base64)\n", file_size);

    // Read base64 encoded data
    char* b64_data = (char*)malloc(file_size + 1);
    size_t bytes_read = fread(b64_data, 1, file_size, f);
    b64_data[bytes_read] = '\0';
    fclose(f);

    // Remove any newlines/whitespace
    size_t clean_len = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        if (b64_data[i] != '\n' && b64_data[i] != '\r' && b64_data[i] != ' ') {
            b64_data[clean_len++] = b64_data[i];
        }
    }
    b64_data[clean_len] = '\0';

    printf("Cleaned base64 length: %zu bytes\n", clean_len);
    printf("First 80 chars: %.80s\n", b64_data);

    // Decode base64
    size_t decoded_len;
    uint8_t* decoded_data = base64_decode(b64_data, clean_len, &decoded_len);

    if (!decoded_data) {
        printf("ERROR: Failed to decode base64 data\n");
        free(b64_data);
        return 1;
    }

    printf("Decoded binary length: %zu bytes\n", decoded_len);

    // Deserialize EncConfig
    EncConfig* enc_config = deserialize_enc_config(decoded_data, decoded_len);

    if (!enc_config) {
        printf("ERROR: Failed to deserialize EncConfig\n");
        free(decoded_data);
        free(b64_data);
        return 1;
    }

    printf("\n✓ Successfully deserialized EncConfig from Python!\n");
    print_hex("Private Key", enc_config->privKey.data, 32);
    print_hex("Public Key", enc_config->pubKey.data, 32);
    print_hex("EncObj Public Key", enc_config->encObj.publicKey.data, 32);
    print_hex("Nonce", enc_config->encObj.nonce.data, 24);
    print_hex("MAC", enc_config->encObj.mac.data, 16);
    printf("Cipher length: %ld bytes\n", enc_config->encObj.cipherLen);

    // In this test, the "ciphertext" is actually plaintext (mock encryption)
    // So we can directly deserialize it as StaticConfig
    printf("\n--- Extracting Embedded StaticConfig ---\n");
    size_t offset = 0;
    StaticConfig* static_config = deserialize_static_config(
        enc_config->encObj.cipherText,
        enc_config->encObj.cipherLen,
        &offset
    );

    if (!static_config) {
        printf("ERROR: Failed to deserialize StaticConfig\n");
        free_enc_config(enc_config);
        free(decoded_data);
        free(b64_data);
        return 1;
    }

    printf("\n✓ Successfully extracted StaticConfig!\n");
    printf("  Build ID: %s\n", static_config->buildID);
    printf("  Deployment ID: %s\n", static_config->deploymentID);
    printf("  Kill Epoch: %d\n", static_config->killEpoch);
    printf("  Interval: %d\n", static_config->interval);
    printf("  Callback: %s\n", static_config->callback);
    print_hex("  C2 Public Key", static_config->c2PubKey.data, 32);

    printf("\n======================================================================\n");
    printf("✓ C Successfully Read Python-Generated Config!\n");
    printf("  Binary format is fully compatible between Python and C!\n");
    printf("======================================================================\n");

    // Cleanup
    free_static_config(static_config);
    free_enc_config(enc_config);
    free(decoded_data);
    free(b64_data);

    return 0;
}
