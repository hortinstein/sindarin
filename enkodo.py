"""
Python implementation of enkodo encryption functionality using pymonocypher.
Compatible with Nim's enkodo library for binary compatibility.
"""

import secrets
import base64
from typing import Tuple, Optional, Union
import monocypher
from flatty import Key, Nonce, Mac, EncObj


def generate_key_pair() -> Tuple[Key, Key]:
    """Generate a public/private key pair using monocypher"""
    private_key_bytes, public_key_bytes = monocypher.generate_key_exchange_key_pair()
    return Key(private_key_bytes), Key(public_key_bytes)


def enc(sender_private_key: Union[Key, bytes], recipient_public_key: Union[Key, bytes], 
        message: bytes) -> EncObj:
    """
    Encrypt message using monocypher compatible with Nim's enkodo.enc
    Returns EncObj with all encryption components
    """
    # Convert Key objects to bytes if needed
    if isinstance(sender_private_key, Key):
        sender_private_key = sender_private_key.data
    if isinstance(recipient_public_key, Key):
        recipient_public_key = recipient_public_key.data
    
    # Generate random nonce
    nonce_bytes = secrets.token_bytes(24)
    
    # Perform key exchange to get shared key  
    shared_key = monocypher.key_exchange(sender_private_key, recipient_public_key)
    
    # Encrypt using monocypher's lock function
    mac_bytes, ciphertext = monocypher.lock(shared_key, nonce_bytes, message)
    
    # Get the public key for this private key
    exchange_public_key = monocypher.compute_key_exchange_public_key(sender_private_key)
    
    return EncObj(
        publicKey=Key(exchange_public_key),
        nonce=Nonce(nonce_bytes),
        mac=Mac(mac_bytes),
        cipherLen=len(ciphertext),
        cipherText=ciphertext
    )


def dec(private_key: Union[Key, bytes], enc_obj: EncObj) -> Optional[bytes]:
    """
    Decrypt EncObj using monocypher compatible with Nim's enkodo.dec
    Returns decrypted bytes or None if decryption fails
    """
    # Convert Key object to bytes if needed
    if isinstance(private_key, Key):
        private_key = private_key.data
    
    try:
        print ("publickey ",list(enc_obj.publicKey.data))
        print ("privateKey ",list(private_key))
        # Perform key exchange to get shared key
        shared_key = monocypher.key_exchange(private_key, enc_obj.publicKey.data)
        print (f"shared key",list(shared_key))
        # Decrypt using monocypher's unlock function
        plaintext = monocypher.unlock(shared_key, enc_obj.nonce.data, 
                                    enc_obj.mac.data, enc_obj.cipherText)
        print("plaintxt:", plaintext)
        return plaintext
    
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


def b64_str(msg: Union[str, bytes]) -> str:
    """Base64 encode string or bytes (safe encoding)"""
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    return base64.urlsafe_b64encode(msg).decode('ascii')


def unb64_str(msg: str) -> bytes:
    """Base64 decode to bytes"""
    return base64.urlsafe_b64decode(msg.encode('ascii'))


def ser_enc_obj(enc_obj: EncObj) -> bytes:
    """Serialize EncObj to bytes using flatty"""
    from flatty import to_flatty
    return to_flatty(enc_obj)


def des_enc_obj(ser_enc_obj: Union[str, bytes]) -> EncObj:
    """Deserialize string/bytes to EncObj using flatty"""
    from flatty import from_flatty
    if isinstance(ser_enc_obj, str):
        data = ser_enc_obj.encode('latin-1')
    else:
        data = ser_enc_obj
    result, _ = from_flatty(data, EncObj)
    return result


def wrap(enc_obj: EncObj) -> str:
    """Wrap EncObj as base64 encoded string"""
    ser_enc_obj_bytes = ser_enc_obj(enc_obj)
    return b64_str(ser_enc_obj_bytes)


def unwrap(b64_ser_enc_obj: str) -> EncObj:
    """Unwrap base64 encoded string to EncObj"""
    ser_enc_obj_bytes = unb64_str(b64_ser_enc_obj)
    return des_enc_obj(ser_enc_obj_bytes)


def wrap_key(key: Key) -> str:
    """Wrap Key as base64 encoded string"""
    from flatty import to_flatty
    ser_key = to_flatty(key)
    return b64_str(ser_key)


def unwrap_key(wrapped_key: str) -> Key:
    """Unwrap base64 encoded string to Key"""
    from flatty import from_flatty
    ser_key_bytes = unb64_str(wrapped_key)
    return from_flatty(ser_key_bytes, Key)


def to_string(data: bytes) -> str:
    """Convert bytes to string (using latin-1 for binary compatibility)"""
    return data.decode('latin-1')


def crypto_key_exchange_public_key(private_key: Union[Key, bytes]) -> Key:
    """Get public key from private key using monocypher"""
    if isinstance(private_key, Key):
        private_key = private_key.data
    
    public_key_bytes = monocypher.compute_key_exchange_public_key(private_key)
    return Key(public_key_bytes)


def encrypt_legacy(sender_private_key: bytes, recipient_public_key: bytes, 
                  message: bytes) -> bytes:
    """
    Legacy encrypt function that returns concatenated bytes
    Compatible with the example in CLAUDE.md
    """
    nonce = secrets.token_bytes(24)
    
    # Perform key exchange to get shared key
    shared_key = monocypher.key_exchange(sender_private_key, recipient_public_key)
    
    # Use monocypher's lock function with shared key
    mac, ciphertext = monocypher.lock(shared_key, nonce, message)
    exchange_key = monocypher.compute_key_exchange_public_key(sender_private_key)
    
    # Return exchange_key + nonce + mac + ciphertext
    return exchange_key + nonce + mac + ciphertext


def decrypt_legacy(private_key: bytes, encrypted_data: bytes) -> Optional[bytes]:
    """
    Legacy decrypt function that takes concatenated bytes
    Compatible with the example in CLAUDE.md  
    """
    if len(encrypted_data) < 72:  # 32 + 24 + 16 minimum
        return None
        
    public_key = encrypted_data[:32]  # First 32 bytes are the public key
    nonce = encrypted_data[32:56]
    mac = encrypted_data[56:72]
    ciphertext = encrypted_data[72:]
    
    try:
        # Perform key exchange to get shared key
        shared_key = monocypher.key_exchange(private_key, public_key)
        
        # Use monocypher's unlock function with shared key
        plaintext = monocypher.unlock(shared_key, nonce, mac, ciphertext)
        return plaintext
    except Exception:
        return None