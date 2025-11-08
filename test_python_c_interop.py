#!/usr/bin/env python3
"""
Python test script to create data for C to read, and read data from C
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from enkodo import generate_key_pair, enc, dec
from flatty import (
    Key, EncObj, EncConfig, StaticConfig, Status, Task, Resp,
    to_flatty, from_flatty
)

def write_bytes_to_file(filename, data):
    """Write bytes to file"""
    with open(filename, 'wb') as f:
        f.write(data)

def read_bytes_from_file(filename):
    """Read bytes from file"""
    with open(filename, 'rb') as f:
        return f.read()

def create_python_data_for_c():
    """Create Python data files for C to read"""
    print("=== Creating Python data for C ===\n")

    # Change to c_implementation directory
    os.chdir('c_implementation')

    # Generate key pairs
    print("1. Generating key pairs...")
    sender_priv, sender_pub = generate_key_pair()
    recipient_priv, recipient_pub = generate_key_pair()

    # Save keys
    write_bytes_to_file("python_sender_private.key", sender_priv.data)
    write_bytes_to_file("python_sender_public.key", sender_pub.data)
    write_bytes_to_file("python_recipient_private.key", recipient_priv.data)
    write_bytes_to_file("python_recipient_public.key", recipient_pub.data)
    print("  ✓ Keys saved\n")

    # Test 1: Encrypt a message
    print("2. Encrypting a message...")
    message = b"Hello from Python! This is a test message."
    print(f"  Original message: {message.decode()}")

    enc_obj = enc(sender_priv, recipient_pub, message)
    serialized_enc_obj = to_flatty(enc_obj)
    write_bytes_to_file("python_encrypted.bin", serialized_enc_obj)
    print(f"  ✓ Encrypted message saved ({len(serialized_enc_obj)} bytes)\n")

    # Test 2: Create StaticConfig
    print("3. Creating StaticConfig...")
    config = StaticConfig(
        buildID="python-build-xyz",
        deploymentID="python-deploy-abc",
        c2PubKey=recipient_pub,
        killEpoch=1700000000,  # Use int32 compatible value
        interval=600,
        callback="https://python-c2.example.com/api"
    )

    serialized_config = to_flatty(config)
    write_bytes_to_file("python_static_config.bin", serialized_config)
    print(f"  ✓ StaticConfig saved ({len(serialized_config)} bytes)")
    print(f"  Build ID: {config.buildID}")
    print(f"  Deployment ID: {config.deploymentID}\n")

    # Test 3: Create EncConfig
    print("4. Creating EncConfig...")

    # Encrypt the config
    config_bytes = to_flatty(config)
    encrypted_config = enc(sender_priv, sender_pub, config_bytes)

    enc_config = EncConfig(
        privKey=sender_priv,
        pubKey=sender_pub,
        encObj=encrypted_config
    )

    serialized_enc_config = to_flatty(enc_config)
    write_bytes_to_file("python_enc_config.bin", serialized_enc_config)
    print(f"  ✓ EncConfig saved ({len(serialized_enc_config)} bytes)\n")

    # Test 4: Create Task
    print("5. Creating Task...")
    task = Task(
        taskId="python-task-789",
        taskNum=99,
        retrieved=False,
        complete=True,
        arg="uname -a",
        resp="Linux test 5.10.0 x86_64"
    )

    serialized_task = to_flatty(task)
    write_bytes_to_file("python_task.bin", serialized_task)
    print(f"  ✓ Task saved ({len(serialized_task)} bytes)")
    print(f"  Task ID: {task.taskId}")
    print(f"  Task Num: {task.taskNum}\n")

    # Test 5: Create Status
    print("6. Creating Status...")
    status = Status(
        ip="192.168.100.50",
        externalIP="198.51.100.25",
        hostname="python-test-host",
        os="Linux",
        arch="aarch64",
        users="python-user,admin",
        bootTime=9876543210
    )

    serialized_status = to_flatty(status)
    write_bytes_to_file("python_status.bin", serialized_status)
    print(f"  ✓ Status saved ({len(serialized_status)} bytes)")
    print(f"  Hostname: {status.hostname}")
    print(f"  OS: {status.os}\n")

    print("=== All Python data files created! ===\n")
    os.chdir('..')

def read_c_data():
    """Read C-generated data files"""
    print("=== Reading C data from Python ===\n")

    os.chdir('c_implementation')

    # Test 1: Read encrypted message
    print("1. Reading C encrypted message...")
    try:
        enc_data = read_bytes_from_file("c_encrypted.bin")
        enc_obj, _ = from_flatty(enc_data, EncObj)
        print(f"  ✓ EncObj deserialized ({len(enc_data)} bytes)")

        # Try to decrypt
        recipient_priv_data = read_bytes_from_file("c_recipient_private.key")
        recipient_priv = Key(recipient_priv_data)

        plaintext = dec(recipient_priv, enc_obj)
        if plaintext:
            print(f"  ✓ Message decrypted: {plaintext.decode()}\n")
        else:
            print("  ✗ Decryption failed\n")
    except FileNotFoundError:
        print("  ⚠ c_encrypted.bin not found - run C test first\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

    # Test 2: Read StaticConfig
    print("2. Reading C StaticConfig...")
    try:
        config_data = read_bytes_from_file("c_static_config.bin")
        config = from_flatty(config_data, StaticConfig)
        print(f"  ✓ StaticConfig deserialized ({len(config_data)} bytes)")
        print(f"  Build ID: {config.buildID}")
        print(f"  Deployment ID: {config.deploymentID}")
        print(f"  Kill Epoch: {config.killEpoch}")
        print(f"  Interval: {config.interval}")
        print(f"  Callback: {config.callback}\n")
    except FileNotFoundError:
        print("  ⚠ c_static_config.bin not found - run C test first\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

    # Test 3: Read EncConfig
    print("3. Reading C EncConfig...")
    try:
        enc_config_data = read_bytes_from_file("c_enc_config.bin")
        enc_config = from_flatty(enc_config_data, EncConfig)
        print(f"  ✓ EncConfig deserialized ({len(enc_config_data)} bytes)")

        # Try to decrypt inner config
        inner_plaintext = dec(enc_config.privKey, enc_config.encObj)
        if inner_plaintext:
            print("  ✓ Inner config decrypted")
            inner_config = from_flatty(inner_plaintext, StaticConfig)
            print(f"  Inner Build ID: {inner_config.buildID}")
            print(f"  Inner Deployment ID: {inner_config.deploymentID}\n")
        else:
            print("  ✗ Inner config decryption failed\n")
    except FileNotFoundError:
        print("  ⚠ c_enc_config.bin not found - run C test first\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

    # Test 4: Read Task
    print("4. Reading C Task...")
    try:
        task_data = read_bytes_from_file("c_task.bin")
        task = from_flatty(task_data, Task)
        print(f"  ✓ Task deserialized ({len(task_data)} bytes)")
        print(f"  Task ID: {task.taskId}")
        print(f"  Task Num: {task.taskNum}")
        print(f"  Retrieved: {task.retrieved}")
        print(f"  Complete: {task.complete}")
        print(f"  Arg: {task.arg}")
        print(f"  Resp: {task.resp}\n")
    except FileNotFoundError:
        print("  ⚠ c_task.bin not found - run C test first\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

    # Test 5: Read Status
    print("5. Reading C Status...")
    try:
        status_data = read_bytes_from_file("c_status.bin")
        status = from_flatty(status_data, Status)
        print(f"  ✓ Status deserialized ({len(status_data)} bytes)")
        print(f"  IP: {status.ip}")
        print(f"  External IP: {status.externalIP}")
        print(f"  Hostname: {status.hostname}")
        print(f"  OS: {status.os}")
        print(f"  Arch: {status.arch}")
        print(f"  Users: {status.users}")
        print(f"  Boot Time: {status.bootTime}\n")
    except FileNotFoundError:
        print("  ⚠ c_status.bin not found - run C test first\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

    print("=== Python read C data complete! ===\n")
    os.chdir('..')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Python/C interoperability tests')
    parser.add_argument('action', choices=['create', 'read', 'both'],
                       help='Action to perform')
    args = parser.parse_args()

    if args.action in ['create', 'both']:
        create_python_data_for_c()

    if args.action in ['read', 'both']:
        read_c_data()
