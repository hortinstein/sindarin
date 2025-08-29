"""
Python implementation of Nim's Flatty serialization library for binary compatibility.
This module provides serialization and deserialization of Nim types using the same binary format.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass


@dataclass
class Key:
    """32-byte key compatible with Nim's Key type"""
    data: bytes
    
    def __init__(self, data: Union[bytes, List[int]]):
        if isinstance(data, list):
            data = bytes(data)
        if len(data) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        self.data = data
    
    def __bytes__(self):
        return self.data
    
    def __getitem__(self, index):
        return self.data[index]
    
    def __len__(self):
        return len(self.data)


@dataclass
class Nonce:
    """24-byte nonce compatible with Nim's Nonce type"""
    data: bytes
    
    def __init__(self, data: Union[bytes, List[int]]):
        if isinstance(data, list):
            data = bytes(data)
        if len(data) != 24:
            raise ValueError("Nonce must be exactly 24 bytes")
        self.data = data
    
    def __bytes__(self):
        return self.data
    
    def __getitem__(self, index):
        return self.data[index]


@dataclass
class Mac:
    """16-byte MAC compatible with Nim's Mac type"""
    data: bytes
    
    def __init__(self, data: Union[bytes, List[int]]):
        if isinstance(data, list):
            data = bytes(data)
        if len(data) != 16:
            raise ValueError("Mac must be exactly 16 bytes")
        self.data = data
    
    def __bytes__(self):
        return self.data
    
    def __getitem__(self, index):
        return self.data[index]


@dataclass
class EncObj:
    """Encryption object compatible with Nim's EncObj type"""
    publicKey: Key
    nonce: Nonce  
    mac: Mac
    cipherLen: int
    cipherText: bytes
    
    def __init__(self, publicKey: Union[Key, bytes, List[int]], 
                 nonce: Union[Nonce, bytes, List[int]], 
                 mac: Union[Mac, bytes, List[int]], 
                 cipherLen: int, 
                 cipherText: Union[bytes, List[int]]):
        self.publicKey = publicKey if isinstance(publicKey, Key) else Key(publicKey)
        self.nonce = nonce if isinstance(nonce, Nonce) else Nonce(nonce)
        self.mac = mac if isinstance(mac, Mac) else Mac(mac)
        self.cipherLen = cipherLen
        self.cipherText = cipherText if isinstance(cipherText, bytes) else bytes(cipherText)


@dataclass
class EncConfig:
    """Encrypted configuration compatible with Nim's EncConfig type"""
    privKey: Key
    pubKey: Key
    encObj: EncObj
    
    def __init__(self, privKey: Union[Key, bytes, List[int]], 
                 pubKey: Union[Key, bytes, List[int]], 
                 encObj: EncObj):
        self.privKey = privKey if isinstance(privKey, Key) else Key(privKey)
        self.pubKey = pubKey if isinstance(pubKey, Key) else Key(pubKey)
        self.encObj = encObj


@dataclass
class StaticConfig:
    """Static configuration compatible with Nim's StaticConfig type"""
    buildID: str
    deploymentID: str
    c2PubKey: Key
    killEpoch: int
    interval: int
    callback: str
    
    def __init__(self, buildID: str = "", deploymentID: str = "", 
                 c2PubKey: Union[Key, bytes, List[int], None] = None, 
                 killEpoch: int = 0, interval: int = 0, callback: str = ""):
        self.buildID = buildID
        self.deploymentID = deploymentID
        self.c2PubKey = c2PubKey if isinstance(c2PubKey, Key) else Key(c2PubKey or bytes(32))
        self.killEpoch = killEpoch
        self.interval = interval
        self.callback = callback


@dataclass  
class Status:
    """Status object compatible with Nim's Status type"""
    ip: str
    externalIP: str
    hostname: str
    os: str
    arch: str
    users: str
    bootTime: int
    
    def __init__(self, ip: str = "", externalIP: str = "", hostname: str = "", 
                 os: str = "", arch: str = "", users: str = "", bootTime: int = 0):
        self.ip = ip
        self.externalIP = externalIP
        self.hostname = hostname
        self.os = os
        self.arch = arch
        self.users = users
        self.bootTime = bootTime


@dataclass
class Callback:
    """Callback object compatible with Nim's Callback type"""
    config: StaticConfig
    status: Status
    
    def __init__(self, config: Optional[StaticConfig] = None, 
                 status: Optional[Status] = None):
        self.config = config or StaticConfig()
        self.status = status or Status()


@dataclass
class Task:
    """Task object compatible with Nim's Task type"""
    taskId: str
    taskNum: int
    retrieved: bool
    complete: bool
    arg: str
    resp: str
    
    def __init__(self, taskId: str = "", taskNum: int = 0, retrieved: bool = False,
                 complete: bool = False, arg: str = "", resp: str = ""):
        self.taskId = taskId
        self.taskNum = taskNum
        self.retrieved = retrieved
        self.complete = complete
        self.arg = arg
        self.resp = resp


@dataclass
class Resp:
    """Response object compatible with Nim's Resp type"""
    taskId: str
    resp: str
    
    def __init__(self, taskId: str = "", resp: str = ""):
        self.taskId = taskId
        self.resp = resp


class FlattySerializer:
    """Flatty-compatible binary serializer"""
    
    @staticmethod
    def serialize_string(s: str) -> bytes:
        """Serialize string with length prefix"""
        data = s.encode('utf-8')
        return struct.pack('<Q', len(data)) + data
    
    @staticmethod
    def deserialize_string(data: bytes, offset: int) -> Tuple[str, int]:
        """Deserialize string with length prefix"""
        if len(data) < offset + 8:
            raise ValueError(f"Not enough data to read string length. Need {offset + 8} bytes, got {len(data)}")
        length = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        if len(data) < offset + length:
            raise ValueError(f"Not enough data to read string content. Need {offset + length} bytes, got {len(data)}")
        string_data = data[offset:offset+length]
        return string_data.decode('utf-8'), offset + length
    
    @staticmethod
    def serialize_int32(value: int) -> bytes:
        """Serialize 32-bit integer"""
        return struct.pack('<i', value)
    
    @staticmethod
    def deserialize_int32(data: bytes, offset: int) -> Tuple[int, int]:
        """Deserialize 32-bit integer"""
        value = struct.unpack('<i', data[offset:offset+4])[0]
        return value, offset + 4
    
    @staticmethod
    def serialize_int64(value: int) -> bytes:
        """Serialize 64-bit integer"""
        return struct.pack('<q', value)
    
    @staticmethod
    def deserialize_int64(data: bytes, offset: int) -> Tuple[int, int]:
        """Deserialize 64-bit integer"""
        value = struct.unpack('<q', data[offset:offset+8])[0]
        return value, offset + 8
    
    @staticmethod
    def serialize_bool(value: bool) -> bytes:
        """Serialize boolean"""
        return b'\x01' if value else b'\x00'
    
    @staticmethod
    def deserialize_bool(data: bytes, offset: int) -> Tuple[bool, int]:
        """Deserialize boolean"""
        return data[offset] == 1, offset + 1
    
    @staticmethod
    def serialize_bytes(data: bytes) -> bytes:
        """Serialize bytes with length prefix"""
        return struct.pack('<Q', len(data)) + data
    
    @staticmethod
    def deserialize_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
        """Deserialize bytes with length prefix"""
        length = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        return data[offset:offset+length], offset + length


def to_flatty(obj: Any) -> bytes:
    """Convert object to Flatty binary format"""
    if isinstance(obj, Key):
        return obj.data
    
    elif isinstance(obj, EncConfig):
        result = b""
        # EncConfig is a ref object in Nim, so add the ref indicator byte
        result += b"\x00"
        result += obj.privKey.data
        result += obj.pubKey.data
        result += to_flatty(obj.encObj)
        return result
    
    elif isinstance(obj, EncObj):
        result = b""
        result += obj.publicKey.data
        result += obj.nonce.data
        result += obj.mac.data
        result += FlattySerializer.serialize_int64(obj.cipherLen)
        result += FlattySerializer.serialize_bytes(obj.cipherText)
        return result
    
    elif isinstance(obj, StaticConfig):
        result = b""
        # StaticConfig is a ref object in Nim, so add the ref indicator byte
        result += b"\x00"  # false = not nil
        result += FlattySerializer.serialize_string(obj.buildID)
        result += FlattySerializer.serialize_string(obj.deploymentID)
        result += obj.c2PubKey.data
        result += FlattySerializer.serialize_int32(obj.killEpoch)
        result += FlattySerializer.serialize_int32(obj.interval)
        result += FlattySerializer.serialize_string(obj.callback)
        return result
    
    elif isinstance(obj, Status):
        result = b""
        result += FlattySerializer.serialize_string(obj.ip)
        result += FlattySerializer.serialize_string(obj.externalIP)
        result += FlattySerializer.serialize_string(obj.hostname)
        result += FlattySerializer.serialize_string(obj.os)
        result += FlattySerializer.serialize_string(obj.arch)
        result += FlattySerializer.serialize_string(obj.users)
        result += FlattySerializer.serialize_int64(obj.bootTime)
        return result
    
    elif isinstance(obj, Callback):
        result = b""
        # Callback is a ref object in Nim, so add the ref indicator byte
        result += b"\x00"  # false = not nil
        result += to_flatty(obj.config)
        result += to_flatty(obj.status)
        return result
    
    elif isinstance(obj, Task):
        result = b""
        result += FlattySerializer.serialize_string(obj.taskId)
        result += FlattySerializer.serialize_int64(obj.taskNum)
        result += FlattySerializer.serialize_bool(obj.retrieved)
        result += FlattySerializer.serialize_bool(obj.complete)
        result += FlattySerializer.serialize_string(obj.arg)
        result += FlattySerializer.serialize_string(obj.resp)
        return result
    
    elif isinstance(obj, Resp):
        result = b""
        result += FlattySerializer.serialize_string(obj.taskId)
        result += FlattySerializer.serialize_string(obj.resp)
        return result
    
    else:
        raise ValueError(f"Unsupported type for serialization: {type(obj)}")


def from_flatty(data: bytes, obj_type: type) -> Any:
    """Convert Flatty binary format to object"""
    offset = 0
    
    if obj_type == Key:
        return Key(data)
    
    elif obj_type == EncConfig:
        # Skip the first byte (might be ref object indicator in Nim)
        if data[0] == 0:
            offset = 1
        
        priv_key = Key(data[offset:offset+32])
        offset += 32
        pub_key = Key(data[offset:offset+32])
        offset += 32
        enc_obj, enc_obj_offset = from_flatty(data[offset:], EncObj)
        offset += enc_obj_offset
        return EncConfig(priv_key, pub_key, enc_obj)
    
    elif obj_type == EncObj:
        public_key = Key(data[offset:offset+32])
        offset += 32
        nonce = Nonce(data[offset:offset+24])
        offset += 24
        mac = Mac(data[offset:offset+16])
        offset += 16
        
        # Read cipherLen (int64) 
        cipher_len, offset = FlattySerializer.deserialize_int64(data, offset)
        
        # Read sequence length (int64) for cipherText seq[byte]
        seq_len, offset = FlattySerializer.deserialize_int64(data, offset)
        
        # Verify that cipherLen matches the sequence length
        if cipher_len != seq_len:
            raise ValueError(f"EncObj deserialization error: cipherLen ({cipher_len}) != seq length ({seq_len})")
        
        # Extract cipher text
        cipher_text = data[offset:offset+seq_len]
        offset += seq_len
        
        return EncObj(public_key, nonce, mac, cipher_len, cipher_text), offset
    
    elif obj_type == StaticConfig:
        # StaticConfig is a ref object in Nim - first byte is nil flag
        is_nil = data[offset] == 1
        offset += 1
        
        if is_nil:
            return None  # Handle nil StaticConfig case
        
        build_id, offset = FlattySerializer.deserialize_string(data, offset)
        deployment_id, offset = FlattySerializer.deserialize_string(data, offset)
        c2_pub_key = Key(data[offset:offset+32])
        offset += 32
        kill_epoch, offset = FlattySerializer.deserialize_int32(data, offset)
        interval, offset = FlattySerializer.deserialize_int32(data, offset)
        callback, offset = FlattySerializer.deserialize_string(data, offset)
        return StaticConfig(build_id, deployment_id, c2_pub_key, kill_epoch, interval, callback)
    
    elif obj_type == Status:
        ip, offset = FlattySerializer.deserialize_string(data, offset)
        external_ip, offset = FlattySerializer.deserialize_string(data, offset)
        hostname, offset = FlattySerializer.deserialize_string(data, offset)
        os, offset = FlattySerializer.deserialize_string(data, offset)
        arch, offset = FlattySerializer.deserialize_string(data, offset)
        users, offset = FlattySerializer.deserialize_string(data, offset)
        boot_time, offset = FlattySerializer.deserialize_int64(data, offset)
        return Status(ip, external_ip, hostname, os, arch, users, boot_time)
    
    elif obj_type == Callback:
        # Callback is a ref object in Nim - first byte is nil flag
        is_nil = data[offset] == 1
        offset += 1
        
        if is_nil:
            return None  # Handle nil Callback case
            
        config = from_flatty(data[offset:], StaticConfig)
        # Calculate offset after StaticConfig - need to recompute with nil flag
        temp_data = to_flatty(config)
        offset += len(temp_data)
        status = from_flatty(data[offset:], Status)
        return Callback(config, status)
    
    elif obj_type == Task:
        task_id, offset = FlattySerializer.deserialize_string(data, offset)
        task_num, offset = FlattySerializer.deserialize_int64(data, offset)
        retrieved, offset = FlattySerializer.deserialize_bool(data, offset)
        complete, offset = FlattySerializer.deserialize_bool(data, offset)
        arg, offset = FlattySerializer.deserialize_string(data, offset)
        resp, offset = FlattySerializer.deserialize_string(data, offset)
        return Task(task_id, task_num, retrieved, complete, arg, resp)
    
    elif obj_type == Resp:
        task_id, offset = FlattySerializer.deserialize_string(data, offset)
        resp, offset = FlattySerializer.deserialize_string(data, offset)
        return Resp(task_id, resp)
    
    else:
        raise ValueError(f"Unsupported type for deserialization: {obj_type}")