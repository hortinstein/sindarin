/**
 * Test full roundtrip: C encrypt -> serialize -> deserialize -> decrypt
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "enkodo.h"
#include "flatty.h"
#include "types.h"

int main() {
    printf("=== Full Roundtrip Test ===\n\n");

    // Generate keys
    printf("1. Generating keys...\n");
    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;
    generate_key_pair(&sender_priv, &sender_pub);
    generate_key_pair(&recipient_priv, &recipient_pub);
    printf("  ✓ Keys generated\n\n");

    // Create a complex message (StaticConfig)
    printf("2. Creating StaticConfig message...\n");
    StaticConfig config = {
        .buildID = "roundtrip-test-123",
        .deploymentID = "deploy-xyz-789",
        .killEpoch = 9999999,
        .interval = 120,
        .callback = "https://c2.roundtrip.test/api/callback"
    };
    memcpy(config.c2PubKey.data, recipient_pub.data, KEY_SIZE);

    // Serialize config
    size_t config_size = calc_static_config_size(&config);
    uint8_t* config_buffer = (uint8_t*)malloc(config_size);
    size_t serialized_size = serialize_static_config(&config, config_buffer);
    printf("  ✓ StaticConfig serialized (%zu bytes)\n\n", serialized_size);

    // Encrypt the serialized config
    printf("3. Encrypting serialized config...\n");
    EncObj enc_obj;
    memset(&enc_obj, 0, sizeof(EncObj));
    int result = enc(&sender_priv, &recipient_pub, config_buffer, serialized_size, &enc_obj);
    assert(result == 0);
    printf("  ✓ Config encrypted\n\n");

    // Serialize the EncObj
    printf("4. Serializing EncObj...\n");
    size_t enc_obj_size = calc_enc_obj_size(&enc_obj);
    uint8_t* enc_obj_buffer = (uint8_t*)malloc(enc_obj_size);
    size_t enc_serialized = serialize_enc_obj(&enc_obj, enc_obj_buffer);
    printf("  ✓ EncObj serialized (%zu bytes)\n\n", enc_serialized);

    // Now simulate sending over network: deserialize EncObj
    printf("5. Deserializing EncObj...\n");
    EncObj received_enc_obj;
    memset(&received_enc_obj, 0, sizeof(EncObj));
    size_t enc_deserialized = deserialize_enc_obj(enc_obj_buffer, enc_serialized, &received_enc_obj);
    assert(enc_deserialized > 0);
    printf("  ✓ EncObj deserialized\n\n");

    // Decrypt the EncObj
    printf("6. Decrypting EncObj...\n");
    uint8_t* decrypted_config = NULL;
    size_t decrypted_size = 0;
    result = dec(&recipient_priv, &received_enc_obj, &decrypted_config, &decrypted_size);
    assert(result == 0);
    printf("  ✓ EncObj decrypted (%zu bytes)\n\n", decrypted_size);

    // Deserialize the decrypted config
    printf("7. Deserializing decrypted StaticConfig...\n");
    StaticConfig received_config;
    memset(&received_config, 0, sizeof(StaticConfig));
    size_t config_deserialized = deserialize_static_config(decrypted_config, decrypted_size,
                                                          &received_config);
    assert(config_deserialized > 0);
    printf("  ✓ StaticConfig deserialized\n\n");

    // Verify the data matches
    printf("8. Verifying data integrity...\n");
    printf("  Original Build ID:     %s\n", config.buildID);
    printf("  Received Build ID:     %s\n", received_config.buildID);
    assert(strcmp(config.buildID, received_config.buildID) == 0);

    printf("  Original Deployment:   %s\n", config.deploymentID);
    printf("  Received Deployment:   %s\n", received_config.deploymentID);
    assert(strcmp(config.deploymentID, received_config.deploymentID) == 0);

    printf("  Original Kill Epoch:   %d\n", config.killEpoch);
    printf("  Received Kill Epoch:   %d\n", received_config.killEpoch);
    assert(config.killEpoch == received_config.killEpoch);

    printf("  Original Interval:     %d\n", config.interval);
    printf("  Received Interval:     %d\n", received_config.interval);
    assert(config.interval == received_config.interval);

    printf("  Original Callback:     %s\n", config.callback);
    printf("  Received Callback:     %s\n", received_config.callback);
    assert(strcmp(config.callback, received_config.callback) == 0);

    printf("  ✓ All fields match!\n\n");

    // Cleanup
    free(config_buffer);
    free(enc_obj_buffer);
    free(decrypted_config);
    free_enc_obj(&enc_obj);
    free_enc_obj(&received_enc_obj);
    free_static_config(&received_config);

    printf("=== Full Roundtrip Test PASSED! ===\n");

    return 0;
}
