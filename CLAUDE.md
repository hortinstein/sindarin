### Sindarin

<div align="center">
  <img src="https://tcgplayer-cdn.tcgplayer.com/product/488291_in_1000x1000.jpg" width="400" alt="Sol Ring - Dwarven (0409) - Commander: The Lord of the Rings: Tales of Middle-earth (LTC)">
</div>

This is an attempt at getting claude code to create a compatible python library with the following .  It is an educational project that attempts to leverage AI for binary compatibility and reading things from another project: 

- it must leverage encryption and serialization that can interface with https://github.com/hortinstein/enkodo/tree/master that will be cloned in temp
- it must be binary compatible with the serialization that enkodo uses: nims Flatty libary: https://github.com/treeform/flatty
- it is okay to create additional debug files, but core functionality should be created in only the following files:
  - ```flatty.py``` implements that serialization and deserialization of nim types
  - ```enkodo.py``` impelments the pymonocypher libraries https://github.com/jetperch/pymonocypher 
  - ```test_encyption.py``` tests the encyption with pytest
  - ```test_serialization.py``` tests the de--serialization with the foundational artifacts in the nim test ```nim_config/debug.config```
- Additionally there are files in nim_config that can generate a debug config.  Please ensure this is run and the python version can read and fully deserialize and decrypt those objects. you can run this test with "cd nim_config && nimble run" which has examples for how nim is creating the file, use this to test deserialization is working correctly!   
- it must also support serialization and deserialization for the following nim types in python:

    ``` nim
    from enkodo/serialize import EncObj, Key, Nonce, Mac
    export Key, Nonce, Mac, EncObj

    #this is used to store the encrypted bytes
    type
    EncConfig* = ref object
        privKey*: Key
        pubKey*: Key
        encObj*: EncObj

    type
    StaticConfig* = ref object
        buildID*: string      #generated on build MAX 12 bytes
        deploymentID*: string #generated on deployment
        c2PubKey*: Key        #to ensure the C2 is the one we want to talk to 
        killEpoch*: int32  #what point should the agent stop calling back and delete
        interval*: int32   #how often should the agent call back
        callback*: string  #where the C2 is MAX LENGTH 256 bytes, should be padded to this everytime to keep size consistent

    type 
    Status* = object
        ip*: string
        externalIP*: string
        hostname*: string
        os*: string
        arch*: string
        users*: string
        bootTime*: int

    type
    Callback* = ref object
        config*: StaticConfig
        status*: Status

    # Define a type for tasks
    type 
    Task* = object
        taskId*: string # Unique identifier for the task
        taskNum*: int # Task number
        retrieved*: bool # Whether the task has been retrieved
        complete*: bool # Whether the task has been completed
        arg*: string # Request data for the task
        resp*: string # Response data for the task

    # Define a type for responses
    type
    Resp* = object
        taskId*: string # Unique identifier for the task
        resp*: string # Response data for the task
    ``` 


Here is an example on how you could to use pymonocypher:

``` python
import monocypher
def generate_key_pair() -> Tuple[bytes, bytes]:
    """Generate a public/private key pair using random bytes"""
    # Use monocypher's built-in key pair generation
    private_key, public_key = monocypher.generate_key_exchange_key_pair()
    return private_key,public_key

def encrypt(sender_private_key: bytes, recipient_public_key: bytes, message: bytes, ) -> bytes:
    """Encrypt message using crypto_lock"""
    nonce = secrets.token_bytes(24)
    
    # Perform key exchange to get shared key
    shared_key = monocypher.key_exchange(sender_private_key, recipient_public_key)
    
    # Use monocypher's lock function with shared key
    mac, ciphertext = monocypher.lock(shared_key, nonce, message)
    exchange_key = monocypher.compute_key_exchange_public_key(sender_private_key)
    # Return nonce + mac + ciphertext
    return exchange_key + nonce + mac  + ciphertext


def decrypt(private_key: bytes,encrypted_data: bytes) -> Optional[bytes]:
    """Decrypt message using crypto_unlock"""
    if len(encrypted_data) < 72:  # 32 + 24 + 16 minimum
        return None
    public_key = encrypted_data[:32]  # First 32 bytes are the public key
    nonce = encrypted_data[32:56]
    mac = encrypted_data[56:72]
    ciphertext = encrypted_data[72:]
    try:
        # Perform key exchange to get shared key
        shared_key = monocypher.key_exchange(private_key, public_key)
        print("shared_key", shared_key)
        # Use monocypher's unlock function with shared key
        plaintext = monocypher.unlock(shared_key, nonce, mac, ciphertext)
        print ("plaintext", plaintext)
        return plaintext
    except Exception:
        print ("decryption failed")
        return None
```
