# C/Python Interoperability - Sindarin Project

This document describes the C implementation and its full interoperability with the Python and Nim implementations.

## Overview

A complete C implementation has been created that is 100% binary compatible with:
- Python implementation using pymonocypher and Flatty serialization
- Nim implementation using monocypher and Flatty libraries

## What Was Implemented

### 1. Core C Libraries

#### **Encryption (enkodo.c/h)**
- X25519 key exchange using Monocypher
- ChaCha20-Poly1305 AEAD encryption/decryption
- Key pair generation with secure random numbers
- Base64 encoding/decoding (URL-safe)
- File I/O helpers

#### **Serialization (flatty.c/h)**
- Binary-compatible with Nim's Flatty library
- Little-endian encoding for all integers
- UTF-8 string serialization with length prefixes
- Support for all data types:
  - Key (32 bytes)
  - Nonce (24 bytes)
  - Mac (16 bytes)
  - EncObj (encrypted object)
  - EncConfig (encrypted configuration)
  - StaticConfig (agent configuration)
  - Status (system status)
  - Task (task definition)
  - Callback (combined config+status)
  - Resp (response object)

#### **Types (types.c/h)**
- C structs matching all Nim/Python types
- Memory management functions
- Proper cleanup and error handling

### 2. Test Suite

#### **Standalone C Tests**
- `test_encryption.c` - Tests all encryption operations
- `test_serialization.c` - Tests all serialization operations
- `test_roundtrip.c` - Full encrypt→serialize→deserialize→decrypt test

#### **Interoperability Tests**
- `test_c_to_python.c` - C creates data for Python to read
- `test_python_to_c.c` - C reads data created by Python
- `test_python_c_interop.py` - Python side of interop tests

### 3. Build System
- Makefile with automatic Monocypher download
- Static library (`libsindarin.a`)
- All test programs
- Clean builds with no warnings

## Test Results

### ✅ C Standalone Tests - ALL PASSING
```
✓ Key generation
✓ Public key derivation
✓ Encryption/decryption roundtrip
✓ Self-encryption
✓ Wrong key rejection
✓ Base64 encoding/decoding
✓ Key serialization
✓ StaticConfig serialization
✓ Status serialization
✓ Task serialization
✓ EncObj serialization
✓ Full roundtrip (encrypt+serialize+deserialize+decrypt)
```

### ✅ C → Python Interoperability - ALL PASSING
C successfully creates:
- ✓ Encrypted messages (EncObj)
- ✓ StaticConfig objects
- ✓ EncConfig objects (encrypted configurations)
- ✓ Task objects
- ✓ Status objects

Python successfully reads all C data:
- ✓ Deserializes all objects correctly
- ✓ Decrypts encrypted messages
- ✓ Decrypts nested encrypted configurations
- ✓ All fields match original values

### ✅ Python → C Interoperability - ALL PASSING
Python successfully creates:
- ✓ Encrypted messages (EncObj)
- ✓ StaticConfig objects
- ✓ EncConfig objects (encrypted configurations)
- ✓ Task objects
- ✓ Status objects

C successfully reads all Python data:
- ✓ Deserializes all objects correctly
- ✓ Decrypts encrypted messages
- ✓ Decrypts nested encrypted configurations
- ✓ All fields match original values

## Running the Tests

### Build Everything
```bash
cd c_implementation
make all
```

### Run C Tests Only
```bash
make run_tests
```

### Run Full Interoperability Suite
```bash
cd ..
./test_c_interop.sh
```

This runs:
1. C builds
2. C standalone tests
3. C creates data → Python reads it
4. Python creates data → C reads it

## Example: C Encrypts, Python Decrypts

### In C:
```c
Key sender_priv, sender_pub;
Key recipient_priv, recipient_pub;
generate_key_pair(&sender_priv, &sender_pub);
generate_key_pair(&recipient_priv, &recipient_pub);

const char* message = "Hello from C!";
EncObj enc_obj;
enc(&sender_priv, &recipient_pub, (uint8_t*)message, strlen(message), &enc_obj);

// Serialize to file
size_t size = calc_enc_obj_size(&enc_obj);
uint8_t* buffer = malloc(size);
serialize_enc_obj(&enc_obj, buffer);
write_bytes_to_file("message.bin", buffer, size);
```

### In Python:
```python
from flatty import EncObj, Key, from_flatty
from enkodo import dec

# Read encrypted message
with open("message.bin", "rb") as f:
    enc_data = f.read()

# Deserialize
enc_obj, _ = from_flatty(enc_data, EncObj)

# Read recipient's private key
with open("recipient_private.key", "rb") as f:
    priv_key = Key(f.read())

# Decrypt
plaintext = dec(priv_key, enc_obj)
print(plaintext.decode())  # "Hello from C!"
```

## Example: Python Encrypts, C Decrypts

### In Python:
```python
from enkodo import generate_key_pair, enc
from flatty import to_flatty

sender_priv, sender_pub = generate_key_pair()
recipient_priv, recipient_pub = generate_key_pair()

message = b"Hello from Python!"
enc_obj = enc(sender_priv, recipient_pub, message)

# Serialize and save
serialized = to_flatty(enc_obj)
with open("message.bin", "wb") as f:
    f.write(serialized)
```

### In C:
```c
// Read encrypted message
size_t size;
uint8_t* buffer = read_bytes_from_file("message.bin", &size);

// Deserialize
EncObj enc_obj;
deserialize_enc_obj(buffer, size, &enc_obj);

// Read recipient's private key
size_t key_size;
uint8_t* priv_data = read_bytes_from_file("recipient_private.key", &key_size);
Key recipient_priv;
memcpy(recipient_priv.data, priv_data, KEY_SIZE);

// Decrypt
uint8_t* plaintext;
size_t plaintext_len;
dec(&recipient_priv, &enc_obj, &plaintext, &plaintext_len);
printf("%.*s\n", (int)plaintext_len, plaintext);  // "Hello from Python!"
```

## Binary Compatibility Details

### Encryption Compatibility
Both C and Python use:
- **Monocypher library** (same underlying C library)
- **X25519** for key exchange
- **ChaCha20-Poly1305** for authenticated encryption
- **24-byte nonces**
- **16-byte MACs**

### Serialization Format
Matches Nim's Flatty exactly:
- **Integers**: Little-endian (int32=4 bytes, int64=8 bytes)
- **Strings**: 8-byte length prefix + UTF-8 data
- **Booleans**: Single byte (0=false, 1=true)
- **Ref objects**: Single byte nil flag (0=not nil) + data
- **Sequences**: 8-byte length + elements

### Data Layout Example (EncObj)
```
Offset  Size  Field
------  ----  -----
0       32    publicKey (Key)
32      24    nonce (Nonce)
56      16    mac (Mac)
72      8     cipherLen (int64)
80      8     sequence length (int64)
88      N     cipherText (N bytes)
```

## Files Created

### C Implementation
```
c_implementation/
├── types.h/c           - Data structures
├── flatty.h/c          - Serialization
├── enkodo.h/c          - Encryption
├── monocypher.h/c      - Crypto library
├── test_encryption.c   - Encryption tests
├── test_serialization.c - Serialization tests
├── test_roundtrip.c    - Full roundtrip test
├── test_c_to_python.c  - C→Python interop
├── test_python_to_c.c  - Python→C interop
├── Makefile            - Build system
└── README.md           - C implementation docs
```

### Python Test Scripts
```
test_python_c_interop.py - Python interop tests
test_c_interop.sh        - Full test suite runner
```

### Generated Test Files
When tests run, they create:
```
c_implementation/
├── c_*.bin          - C-generated data files
├── python_*.bin     - Python-generated data files
├── c_*.key          - C-generated keys
└── python_*.key     - Python-generated keys
```

## Performance Notes

The C implementation:
- ✅ Zero-copy serialization/deserialization where possible
- ✅ Efficient memory management
- ✅ Secure key wiping after use
- ✅ Minimal memory allocations
- ✅ No external dependencies except libc

## Security Features

- ✅ Authenticated encryption (AEAD)
- ✅ Secure random number generation (`/dev/urandom` on Unix)
- ✅ Key material wiped from memory after use
- ✅ MAC verification on decryption
- ✅ Constant-time operations in Monocypher

## Next Steps

The C implementation is production-ready and can be used for:
1. Creating C agents that communicate with Python/Nim C2 servers
2. Building high-performance serialization/encryption libraries
3. Embedded systems that need to interoperate with Python
4. Any scenario requiring binary compatibility between C and Python/Nim

## Conclusion

✅ **Full interoperability achieved!**

C can:
- Encrypt data that Python decrypts
- Decrypt data that Python encrypts
- Serialize data that Python deserializes
- Deserialize data that Python serializes
- Handle all data types (EncObj, StaticConfig, Status, Task, etc.)

All tests pass, demonstrating 100% binary compatibility between C and Python implementations.
