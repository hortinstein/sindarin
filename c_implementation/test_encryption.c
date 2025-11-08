/**
 * Test encryption/decryption functionality
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "enkodo.h"
#include "types.h"

void test_key_generation() {
    printf("Testing key generation...\n");

    Key priv, pub;
    int result = generate_key_pair(&priv, &pub);
    assert(result == 0);

    // Keys should be different
    assert(memcmp(priv.data, pub.data, KEY_SIZE) != 0);

    printf("  ✓ Key generation successful\n");
}

void test_public_key_derivation() {
    printf("Testing public key derivation...\n");

    Key priv, pub1, pub2;
    generate_key_pair(&priv, &pub1);

    // Derive public key from private key
    crypto_key_exchange_public_key(&priv, &pub2);

    // Should match the original public key
    assert(memcmp(pub1.data, pub2.data, KEY_SIZE) == 0);

    printf("  ✓ Public key derivation successful\n");
}

void test_enc_dec_roundtrip() {
    printf("Testing encryption/decryption roundtrip...\n");

    // Generate key pairs
    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;
    generate_key_pair(&sender_priv, &sender_pub);
    generate_key_pair(&recipient_priv, &recipient_pub);

    // Test message
    const char* message = "Hello, World! This is a test message.";
    size_t message_len = strlen(message);

    // Encrypt
    EncObj enc_obj;
    memset(&enc_obj, 0, sizeof(EncObj));
    int result = enc(&sender_priv, &recipient_pub,
                    (const uint8_t*)message, message_len, &enc_obj);
    assert(result == 0);
    assert(enc_obj.cipherLen == (int64_t)message_len);

    // Decrypt
    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;
    result = dec(&recipient_priv, &enc_obj, &plaintext, &plaintext_len);
    assert(result == 0);
    assert(plaintext_len == message_len);
    assert(memcmp(plaintext, message, message_len) == 0);

    printf("  ✓ Encryption/decryption roundtrip successful\n");

    free(plaintext);
    free_enc_obj(&enc_obj);
}

void test_self_encryption() {
    printf("Testing self-encryption...\n");

    Key priv, pub;
    generate_key_pair(&priv, &pub);

    const char* message = "Self-encrypted message";
    size_t message_len = strlen(message);

    EncObj enc_obj;
    memset(&enc_obj, 0, sizeof(EncObj));
    enc(&priv, &pub, (const uint8_t*)message, message_len, &enc_obj);

    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;
    dec(&priv, &enc_obj, &plaintext, &plaintext_len);

    assert(plaintext_len == message_len);
    assert(memcmp(plaintext, message, message_len) == 0);

    printf("  ✓ Self-encryption successful\n");

    free(plaintext);
    free_enc_obj(&enc_obj);
}

void test_wrong_key() {
    printf("Testing decryption with wrong key...\n");

    Key sender_priv, sender_pub;
    Key recipient_priv, recipient_pub;
    Key wrong_priv, wrong_pub;
    generate_key_pair(&sender_priv, &sender_pub);
    generate_key_pair(&recipient_priv, &recipient_pub);
    generate_key_pair(&wrong_priv, &wrong_pub);

    const char* message = "Secret message";
    EncObj enc_obj;
    memset(&enc_obj, 0, sizeof(EncObj));
    enc(&sender_priv, &recipient_pub,
        (const uint8_t*)message, strlen(message), &enc_obj);

    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;
    int result = dec(&wrong_priv, &enc_obj, &plaintext, &plaintext_len);

    // Should fail
    assert(result != 0);
    assert(plaintext == NULL);

    printf("  ✓ Wrong key correctly rejected\n");

    free_enc_obj(&enc_obj);
}

void test_base64_encoding() {
    printf("Testing base64 encoding...\n");

    const char* test_str = "Hello, World!";
    size_t test_len = strlen(test_str);

    char* encoded = b64_encode((const uint8_t*)test_str, test_len);
    assert(encoded != NULL);

    size_t decoded_len;
    uint8_t* decoded = b64_decode(encoded, &decoded_len);
    assert(decoded != NULL);
    assert(decoded_len == test_len);
    assert(memcmp(decoded, test_str, test_len) == 0);

    printf("  ✓ Base64 encoding/decoding successful\n");

    free(encoded);
    free(decoded);
}

int main() {
    printf("=== C Encryption Tests ===\n\n");

    test_key_generation();
    test_public_key_derivation();
    test_enc_dec_roundtrip();
    test_self_encryption();
    test_wrong_key();
    test_base64_encoding();

    printf("\n=== All tests passed! ===\n");

    return 0;
}
