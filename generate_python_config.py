#!/usr/bin/env python3
"""
Generate a Python EncConfig and serialize it to test cross-platform compatibility.
This version works without monocypher by using mock encryption data.
"""

import base64
import secrets
from flatty import (
    Key, Nonce, Mac, EncObj, EncConfig, StaticConfig,
    to_flatty
)

def generate_test_config():
    """Generate a test EncConfig with known values for testing"""

    print("=" * 70)
    print("Python Config Generator")
    print("=" * 70)

    # Generate random keys for testing
    priv_key_bytes = secrets.token_bytes(32)
    pub_key_bytes = secrets.token_bytes(32)

    priv_key = Key(priv_key_bytes)
    pub_key = Key(pub_key_bytes)

    print(f"\nGenerated Keys:")
    print(f"Private Key: {priv_key_bytes.hex()}")
    print(f"Public Key:  {pub_key_bytes.hex()}")

    # Create a StaticConfig with test data
    static_config = StaticConfig(
        buildID="python-build-001",
        deploymentID="python-deploy-001",
        c2PubKey=Key(secrets.token_bytes(32)),
        killEpoch=1234567890,
        interval=60,
        callback="https://python-c2.example.com/callback"
    )

    print(f"\nStatic Config:")
    print(f"  Build ID: {static_config.buildID}")
    print(f"  Deployment ID: {static_config.deploymentID}")
    print(f"  Kill Epoch: {static_config.killEpoch}")
    print(f"  Interval: {static_config.interval}")
    print(f"  Callback: {static_config.callback}")
    print(f"  C2 Public Key: {static_config.c2PubKey.data.hex()[:32]}...")

    # Serialize the static config
    static_config_bytes = to_flatty(static_config)
    print(f"\nSerialized StaticConfig: {len(static_config_bytes)} bytes")

    # Create a mock encrypted object (for testing serialization without monocypher)
    # In real use, this would be encrypted with monocypher
    enc_pub_key = Key(secrets.token_bytes(32))
    nonce = Nonce(secrets.token_bytes(24))
    mac = Mac(secrets.token_bytes(16))

    # For this test, we'll use the plaintext as "ciphertext"
    # (not actually encrypted, just for structure testing)
    enc_obj = EncObj(
        publicKey=enc_pub_key,
        nonce=nonce,
        mac=mac,
        cipherLen=len(static_config_bytes),
        cipherText=static_config_bytes  # Mock "encrypted" data
    )

    print(f"\nEncObj:")
    print(f"  Public Key: {enc_pub_key.data.hex()[:32]}...")
    print(f"  Nonce: {nonce.data.hex()}")
    print(f"  MAC: {mac.data.hex()}")
    print(f"  Cipher Length: {enc_obj.cipherLen}")

    # Create EncConfig
    enc_config = EncConfig(
        privKey=priv_key,
        pubKey=pub_key,
        encObj=enc_obj
    )

    # Serialize to binary
    binary_data = to_flatty(enc_config)
    print(f"\nSerialized EncConfig: {len(binary_data)} bytes")

    # Encode to base64 (URL-safe like Nim does)
    b64_data = base64.urlsafe_b64encode(binary_data).decode('ascii')
    print(f"Base64 encoded: {len(b64_data)} characters")

    return b64_data, binary_data, enc_config

def main():
    # Generate config
    b64_data, binary_data, enc_config = generate_test_config()

    # Save to file
    output_file = "python_generated.config"
    with open(output_file, 'w') as f:
        f.write(b64_data)

    print(f"\n✓ Saved to: {output_file}")
    print(f"\nFirst 100 characters of base64:")
    print(b64_data[:100])

    # Test round-trip deserialization
    print("\n" + "=" * 70)
    print("Testing Round-Trip Deserialization")
    print("=" * 70)

    from flatty import from_flatty

    # Decode and deserialize
    decoded_binary = base64.urlsafe_b64decode(b64_data.encode('ascii'))
    deserialized_config = from_flatty(decoded_binary, EncConfig)

    print(f"\n✓ Successfully deserialized!")
    print(f"  Private Key matches: {deserialized_config.privKey.data == enc_config.privKey.data}")
    print(f"  Public Key matches: {deserialized_config.pubKey.data == enc_config.pubKey.data}")
    print(f"  Cipher length matches: {deserialized_config.encObj.cipherLen == enc_config.encObj.cipherLen}")

    # Try to deserialize the "encrypted" data (which is actually plaintext in this test)
    print(f"\nExtracting embedded StaticConfig...")
    embedded_config = from_flatty(deserialized_config.encObj.cipherText, StaticConfig)
    print(f"  Build ID: {embedded_config.buildID}")
    print(f"  Deployment ID: {embedded_config.deploymentID}")
    print(f"  Kill Epoch: {embedded_config.killEpoch}")
    print(f"  Interval: {embedded_config.interval}")

    print("\n" + "=" * 70)
    print("✓ Python Config Generation Complete!")
    print("=" * 70)

if __name__ == "__main__":
    main()
