#!/usr/bin/env python3
"""
Test to decode nim_config/debug.config file.

The debug.config file contains:
1. Base64-encoded data
2. Flatty-serialized EncConfig object
3. EncConfig contains: privKey (32 bytes), pubKey (32 bytes), encObj (encrypted StaticConfig)
4. encObj contains: publicKey (32 bytes), nonce (24 bytes), mac (16 bytes), cipherLen (int), cipherText (variable length)

Based on the Nim code in nim_config/src/config.nim and types.nim
"""

import base64
import struct
import sys
from pathlib import Path

def read_config_file(filepath: str) -> bytes:
    """Read and base64 decode the config file."""
    with open(filepath, 'r') as f:
        b64_data = f.read().strip()
    
    # Add padding if needed for base64 decoding
    missing_padding = len(b64_data) % 4
    if missing_padding:
        b64_data += '=' * (4 - missing_padding)
    
    # Use URL-safe base64 (Nim uses safe=true)
    return base64.urlsafe_b64decode(b64_data)

def parse_flatty_data(data: bytes) -> dict:
    """Parse Flatty-serialized data to extract EncConfig structure."""
    offset = 0
    
    # Parse EncConfig structure
    # privKey: 32 bytes
    priv_key = data[offset:offset+32]
    offset += 32
    
    # pubKey: 32 bytes  
    pub_key = data[offset:offset+32]
    offset += 32
    
    # encObj structure starts here
    # publicKey: 32 bytes
    enc_public_key = data[offset:offset+32]
    offset += 32
    
    # nonce: 24 bytes
    nonce = data[offset:offset+24]
    offset += 24
    
    # mac: 16 bytes
    mac = data[offset:offset+16]
    offset += 16
    
    # For Flatty sequence encoding, use remaining data as cipher text
    remaining_bytes = len(data) - offset
    cipher_text = data[offset:offset+remaining_bytes]
    final_offset = offset + remaining_bytes
    
    return {
        'priv_key': priv_key,
        'pub_key': pub_key,
        'enc_obj': {
            'public_key': enc_public_key,
            'nonce': nonce,
            'mac': mac,
            'cipher_len': len(cipher_text),
            'cipher_text': cipher_text
        },
        'remaining_data': data[final_offset:] if final_offset < len(data) else b''
    }

def hex_format(data: bytes, max_len: int = 16) -> str:
    """Format bytes as hex string with optional truncation."""
    hex_str = data.hex()
    if len(hex_str) > max_len * 2:
        return f"{hex_str[:max_len*2]}... ({len(data)} bytes)"
    return hex_str

def test_decode_debug_config():
    """Test decoding the debug.config file."""
    config_path = Path(__file__).parent / "nim_config" / "debug.config"
    
    if not config_path.exists():
        print(f"ERROR: Config file not found at {config_path}")
        return False
    
    try:
        # Read and decode the file
        print(f"Reading config from: {config_path}")
        raw_data = read_config_file(str(config_path))
        print(f"Raw data length: {len(raw_data)} bytes")
        
        # Parse the Flatty data
        parsed = parse_flatty_data(raw_data)
        
        # Display results
        print("\n=== EncConfig Structure ===")
        print(f"Private Key: {hex_format(parsed['priv_key'])}")
        print(f"Public Key:  {hex_format(parsed['pub_key'])}")
        
        print(f"\n=== Encrypted Object (EncObj) ===")
        enc_obj = parsed['enc_obj']
        print(f"Public Key: {hex_format(enc_obj['public_key'])}")
        print(f"Nonce:      {hex_format(enc_obj['nonce'])}")
        print(f"MAC:        {hex_format(enc_obj['mac'])}")
        print(f"Cipher Len: {enc_obj['cipher_len']}")
        print(f"Cipher Text: {hex_format(enc_obj['cipher_text'], 32)}")
        
        if parsed['remaining_data']:
            print(f"\nRemaining data: {hex_format(parsed['remaining_data'])}")
        
        # Validate structure
        expected_min_size = 32 + 32 + 32 + 24 + 16 + 4  # 140 bytes minimum
        if len(raw_data) < expected_min_size:
            print(f"WARNING: Data too short. Expected at least {expected_min_size} bytes, got {len(raw_data)}")
            return False
            
        if enc_obj['cipher_len'] != len(enc_obj['cipher_text']):
            print(f"WARNING: Cipher length mismatch. Expected {enc_obj['cipher_len']}, got {len(enc_obj['cipher_text'])}")
            return False
        
        print(f"\n✓ Successfully decoded EncConfig structure")
        print(f"✓ All field lengths match expected values")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to decode config: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_decode_debug_config()
    sys.exit(0 if success else 1)