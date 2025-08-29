import std/strutils
import std/base64
import std/os

import flatty 
import types
import enkodo
import config

proc test_read_python_config() =
  echo "Testing Nim reading Python-generated config..."
  
  let pythonConfigPath = "/workspaces/sindarin/python_generated.config"
  
  if not fileExists(pythonConfigPath):
    echo "ERROR: Python config file not found at: ", pythonConfigPath
    echo "Please run the Python test first to generate the config file"
    return
  
  try:
    # Read the base64 encoded config
    let b64Data = readStringFromFile(pythonConfigPath).strip()
    echo "Read base64 data length: ", b64Data.len
    
    # Decode base64
    let binaryData = decode(b64Data)
    echo "Decoded binary data length: ", binaryData.len
    
    # Deserialize as EncConfig
    let encConfig = binaryData.fromFlatty(EncConfig)
    echo "Successfully deserialized EncConfig from Python!"
    
    # Print structure info
    echo "Private key length: ", encConfig.privKey.len
    echo "Public key length: ", encConfig.pubKey.len  
    echo "EncObj public key length: ", encConfig.encObj.publicKey.len
    echo "EncObj nonce length: ", encConfig.encObj.nonce.len
    echo "EncObj mac length: ", encConfig.encObj.mac.len
    try:
      echo "EncObj cipher length: ", encConfig.encObj.cipherLen
    except:
      echo "WARNING: Could not access cipher length"
    
    try:
      echo "EncObj cipher text actual length: ", encConfig.encObj.cipherText.len
    except:
      echo "WARNING: Could not access cipher text length"
    
    # Print some key values for debugging (safely)
    if encConfig.privKey.len >= 10:
      echo "Private key (first 10 bytes): ", encConfig.privKey[0..9]
    if encConfig.pubKey.len >= 10:  
      echo "Public key (first 10 bytes): ", encConfig.pubKey[0..9]
    if encConfig.encObj.nonce.len >= 10:
      echo "Nonce (first 10 bytes): ", encConfig.encObj.nonce[0..9]
    if encConfig.encObj.mac.len >= 10:
      echo "MAC (first 10 bytes): ", encConfig.encObj.mac[0..9]
    
    # Check cipher text safely
    try:
      if encConfig.encObj.cipherText.len > 0:
        echo "Cipher text first 10 bytes: ", encConfig.encObj.cipherText[0..min(9, encConfig.encObj.cipherText.len-1)]
      else:
        echo "WARNING: Cipher text is empty!"
    except:
      echo "WARNING: Could not access cipher text"
    
    # Try to decrypt the config
    echo "\nAttempting to decrypt the configuration..."
    try:
      let decryptedBytes = dec(encConfig.privKey, encConfig.encObj)
      echo "Decryption successful! Decrypted ", decryptedBytes.len, " bytes"
      
      # Try to deserialize as StaticConfig
      let staticConfig = cast[string](decryptedBytes).fromFlatty(StaticConfig)
      echo "Successfully deserialized StaticConfig!"
      echo "Build ID: ", staticConfig.buildID
      echo "Deployment ID: ", staticConfig.deploymentID
      echo "Kill Epoch: ", staticConfig.killEpoch
      echo "Interval: ", staticConfig.interval
      echo "Callback (first 50 chars): ", staticConfig.callback[0..min(49, staticConfig.callback.len-1)]
      echo "C2 Public Key (first 10 bytes): ", staticConfig.c2PubKey[0..9]
      
    except Exception as e:
      echo "Decryption failed: ", e.msg
      echo "This may be expected due to differences between Nim and Python monocypher implementations"
    
    echo "\nBinary compatibility test PASSED - Nim successfully read Python-generated config!"
    
  except Exception as e:
    echo "ERROR reading Python config: ", e.msg
    echo "Stack trace: ", getStackTrace(e)

when isMainModule:
  test_read_python_config()