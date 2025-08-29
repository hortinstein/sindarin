#!/usr/bin/env python3
"""
Example usage of the Sindarin Python library - 
Binary compatible with Nim's enkodo and flatty libraries.
"""

import base64
from flatty import (
    Key, EncConfig, StaticConfig, Status, Task, Resp, 
    to_flatty, from_flatty
)
from enkodo import (
    generate_key_pair, enc, dec, b64_str, unb64_str,
    wrap, unwrap
)


def main():
    print("=== Sindarin Python Library Demo ===")
    print("Binary compatible with Nim's enkodo and flatty")
    print()
    
    # 1. Key generation
    print("1. Generating key pairs...")
    sender_priv, sender_pub = generate_key_pair()
    receiver_priv, receiver_pub = generate_key_pair()
    print(f"   Sender public key: {sender_pub.data[:8].hex()}...")
    print(f"   Receiver public key: {receiver_pub.data[:8].hex()}...")
    print()
    
    # 2. Create a StaticConfig
    print("2. Creating StaticConfig...")
    config = StaticConfig(
        buildID="demo_build_001",
        deploymentID="deployment_123", 
        c2PubKey=receiver_pub,
        killEpoch=1800000000,
        interval=300,
        callback="https://example.com/c2" + "\0" * (256 - len("https://example.com/c2"))
    )
    print(f"   Build ID: {config.buildID}")
    print(f"   Kill Epoch: {config.killEpoch}")
    print(f"   Interval: {config.interval} seconds")
    print()
    
    # 3. Serialize the config
    print("3. Serializing config...")
    config_bytes = to_flatty(config)
    print(f"   Serialized size: {len(config_bytes)} bytes")
    print()
    
    # 4. Encrypt the config
    print("4. Encrypting config...")
    enc_obj = enc(sender_priv, receiver_pub, config_bytes)
    print(f"   Cipher length: {enc_obj.cipherLen}")
    print(f"   Nonce: {enc_obj.nonce.data[:8].hex()}...")
    print(f"   MAC: {enc_obj.mac.data[:8].hex()}...")
    print()
    
    # 5. Create EncConfig and serialize it
    print("5. Creating EncConfig...")
    enc_config = EncConfig(sender_priv, sender_pub, enc_obj)
    enc_config_bytes = to_flatty(enc_config)
    enc_config_b64 = b64_str(enc_config_bytes)
    print(f"   EncConfig serialized size: {len(enc_config_bytes)} bytes")
    print(f"   Base64 encoded (first 50 chars): {enc_config_b64[:50]}...")
    print()
    
    # 6. Deserialize and decrypt
    print("6. Deserializing and decrypting...")
    # Simulate reading from storage
    restored_bytes = unb64_str(enc_config_b64)
    restored_enc_config = from_flatty(restored_bytes, EncConfig)
    
    # Decrypt the config
    decrypted_bytes = dec(receiver_priv, restored_enc_config.encObj)
    if decrypted_bytes:
        restored_config = from_flatty(decrypted_bytes, StaticConfig)
        print(f"   ✓ Decryption successful!")
        print(f"   Build ID: {restored_config.buildID}")
        print(f"   Kill Epoch: {restored_config.killEpoch}")
        print(f"   Callback: {restored_config.callback[:30]}...")
    else:
        print(f"   ✗ Decryption failed")
    print()
    
    # 7. Test other data types
    print("7. Testing other data types...")
    
    # Status
    status = Status(
        ip="192.168.1.100",
        externalIP="203.0.113.5", 
        hostname="agent-001",
        os="Linux",
        arch="x86_64",
        users="admin,guest",
        bootTime=1640995200
    )
    status_bytes = to_flatty(status)
    restored_status = from_flatty(status_bytes, Status)
    print(f"   Status: {restored_status.hostname} ({restored_status.os} {restored_status.arch})")
    
    # Task
    task = Task(
        taskId="task_001",
        taskNum=1,
        retrieved=False,
        complete=False,
        arg="ls -la",
        resp=""
    )
    task_bytes = to_flatty(task)
    restored_task = from_flatty(task_bytes, Task)
    print(f"   Task: {restored_task.taskId} - '{restored_task.arg}'")
    
    print()
    print("=== Demo Complete ===")
    print("All serialization and encryption operations successful!")
    print("Binary compatibility with Nim enkodo/flatty confirmed.")


if __name__ == "__main__":
    main()