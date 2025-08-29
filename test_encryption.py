"""
Test encryption functionality using pytest.
Tests pymonocypher integration and compatibility with Nim's enkodo library.
"""

import pytest
import secrets
from enkodo import (
    generate_key_pair, enc, dec, b64_str, unb64_str, 
    wrap, unwrap, wrap_key, unwrap_key,
    crypto_key_exchange_public_key
)
from flatty import Key, Nonce, Mac, EncObj


class TestKeyGeneration:
    """Test key generation functionality"""
    
    def test_generate_key_pair(self):
        """Test key pair generation"""
        priv_key, pub_key = generate_key_pair()
        
        assert isinstance(priv_key, Key)
        assert isinstance(pub_key, Key)
        assert len(priv_key.data) == 32
        assert len(pub_key.data) == 32
        assert priv_key.data != pub_key.data
    
    def test_crypto_key_exchange_public_key(self):
        """Test public key derivation from private key"""
        priv_key, pub_key = generate_key_pair()
        
        # Derive public key from private key
        derived_pub_key = crypto_key_exchange_public_key(priv_key)
        
        assert isinstance(derived_pub_key, Key)
        assert derived_pub_key.data == pub_key.data


class TestEncryption:
    """Test encryption and decryption functionality"""
    
    def test_enc_dec_roundtrip(self):
        """Test encryption and decryption roundtrip"""
        # Generate key pairs for sender and recipient
        sender_priv, sender_pub = generate_key_pair()
        recipient_priv, recipient_pub = generate_key_pair()
        
        # Test message
        message = b"Hello, World! This is a test message."
        
        # Encrypt message
        enc_obj = enc(sender_priv, recipient_pub, message)
        
        # Verify EncObj structure
        assert isinstance(enc_obj, EncObj)
        assert isinstance(enc_obj.publicKey, Key)
        assert isinstance(enc_obj.nonce, Nonce)
        assert isinstance(enc_obj.mac, Mac)
        assert enc_obj.cipherLen == len(enc_obj.cipherText)
        assert len(enc_obj.cipherText) > 0
        
        # Decrypt message
        decrypted = dec(recipient_priv, enc_obj)
        
        assert decrypted is not None
        assert decrypted == message
    
    def test_enc_dec_self_encryption(self):
        """Test self-encryption (same key pair)"""
        priv_key, pub_key = generate_key_pair()
        message = b"Self-encrypted message"
        
        # Encrypt to self
        enc_obj = enc(priv_key, pub_key, message)
        decrypted = dec(priv_key, enc_obj)
        
        assert decrypted == message
    
    def test_enc_dec_different_messages(self):
        """Test encryption of different message types"""
        sender_priv, sender_pub = generate_key_pair()
        recipient_priv, recipient_pub = generate_key_pair()
        
        test_messages = [
            b"",  # Empty message
            b"Short",  # Short message
            b"A" * 1000,  # Long message
            bytes(range(256)),  # Binary data
        ]
        
        for message in test_messages:
            enc_obj = enc(sender_priv, recipient_pub, message)
            decrypted = dec(recipient_priv, enc_obj)
            assert decrypted == message, f"Failed for message of length {len(message)}"
    
    def test_dec_wrong_key(self):
        """Test decryption with wrong key fails"""
        sender_priv, sender_pub = generate_key_pair()
        recipient_priv, recipient_pub = generate_key_pair()
        wrong_priv, wrong_pub = generate_key_pair()
        
        message = b"Secret message"
        enc_obj = enc(sender_priv, recipient_pub, message)
        
        # Try to decrypt with wrong key
        decrypted = dec(wrong_priv, enc_obj)
        assert decrypted is None
    
    def test_dec_corrupted_data(self):
        """Test decryption with corrupted data fails"""
        sender_priv, sender_pub = generate_key_pair()
        recipient_priv, recipient_pub = generate_key_pair()
        
        message = b"Original message"
        enc_obj = enc(sender_priv, recipient_pub, message)
        
        # Corrupt the MAC
        corrupted_enc_obj = EncObj(
            enc_obj.publicKey,
            enc_obj.nonce,
            Mac(bytes(16)),  # All zeros MAC
            enc_obj.cipherLen,
            enc_obj.cipherText
        )
        
        decrypted = dec(recipient_priv, corrupted_enc_obj)
        assert decrypted is None




class TestSerialization:
    """Test serialization and encoding functions"""
    
    def test_b64_str_roundtrip(self):
        """Test base64 encoding/decoding"""
        test_strings = ["Hello", "World!", "", "Special chars: åäö"]
        
        for s in test_strings:
            encoded = b64_str(s)
            decoded = unb64_str(encoded)
            assert decoded == s.encode('utf-8')
    
    def test_b64_str_bytes(self):
        """Test base64 encoding with bytes input"""
        test_bytes = b"Binary data \x00\x01\x02\xff"
        encoded = b64_str(test_bytes)
        
        # Decode manually to verify
        import base64
        decoded = base64.urlsafe_b64decode(encoded.encode('ascii'))
        assert decoded == test_bytes
    
    def test_wrap_unwrap_enc_obj(self):
        """Test EncObj wrapping/unwrapping"""
        priv_key, pub_key = generate_key_pair()
        message = b"Test message for wrapping"
        
        # Create EncObj
        enc_obj = enc(priv_key, pub_key, message)
        
        # Wrap and unwrap
        wrapped = wrap(enc_obj)
        unwrapped = unwrap(wrapped)
        
        # Verify structure is preserved
        assert unwrapped.publicKey.data == enc_obj.publicKey.data
        assert unwrapped.nonce.data == enc_obj.nonce.data
        assert unwrapped.mac.data == enc_obj.mac.data
        assert unwrapped.cipherLen == enc_obj.cipherLen
        assert unwrapped.cipherText == enc_obj.cipherText
        
        # Verify decryption still works
        decrypted = dec(priv_key, unwrapped)
        assert decrypted == message
    
    def test_wrap_unwrap_key(self):
        """Test Key wrapping/unwrapping"""
        priv_key, pub_key = generate_key_pair()
        
        # Wrap and unwrap keys
        wrapped_priv = wrap_key(priv_key)
        wrapped_pub = wrap_key(pub_key)
        
        unwrapped_priv = unwrap_key(wrapped_priv)
        unwrapped_pub = unwrap_key(wrapped_pub)
        
        assert unwrapped_priv.data == priv_key.data
        assert unwrapped_pub.data == pub_key.data


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_invalid_key_sizes(self):
        """Test invalid key sizes are rejected"""
        with pytest.raises(ValueError):
            Key(b"too_short")
        
        with pytest.raises(ValueError):
            Key(b"way_too_long_key_data_exceeding_32_bytes")
        
        with pytest.raises(ValueError):
            Nonce(b"short")
        
        with pytest.raises(ValueError):
            Mac(b"short")
    
    def test_key_from_list(self):
        """Test Key creation from list"""
        key_list = list(range(32))
        key = Key(key_list)
        assert key.data == bytes(key_list)
    
    def test_enc_obj_creation(self):
        """Test EncObj creation with different input types"""
        pub_key = Key(secrets.token_bytes(32))
        nonce = Nonce(secrets.token_bytes(24))
        mac = Mac(secrets.token_bytes(16))
        cipher_text = b"test cipher"
        
        # Test with Key/Nonce/Mac objects
        enc_obj1 = EncObj(pub_key, nonce, mac, len(cipher_text), cipher_text)
        assert enc_obj1.publicKey.data == pub_key.data
        
        # Test with bytes
        enc_obj2 = EncObj(pub_key.data, nonce.data, mac.data, len(cipher_text), cipher_text)
        assert enc_obj2.publicKey.data == pub_key.data
        
        # Test with lists
        enc_obj3 = EncObj(list(pub_key.data), list(nonce.data), list(mac.data), 
                         len(cipher_text), list(cipher_text))
        assert enc_obj3.publicKey.data == pub_key.data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])