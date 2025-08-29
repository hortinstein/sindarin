import std/oids
import std/strutils
import std/json
import std/parseutils
import std/base64

import flatty 

import types
import enkodo
from monocypher import crypto_key_exchange_public_key

let URL_MAX_LEN = 256
let BUILD_ID_LEN = 12  

proc serEncConfig*(encConfig:EncConfig): string = 
  result = toFlatty(encConfig)

proc desEncConfig*(serEncMsg:string): EncConfig = 
  result = serEncMsg.fromFlatty(EncConfig)

proc serConfig*(config:StaticConfig): string = 
  result = toFlatty(config)

proc desConfig*(serEncMsg:string): StaticConfig = 
  result = serEncMsg.fromFlatty(StaticConfig)
  
proc padUrl*(url:string): string =
  let urlLen = url.len
  if urlLen == URL_MAX_LEN: return url
  if urlLen < URL_MAX_LEN:
    result = url & "\0".repeat(URL_MAX_LEN-urlLen)
  else:
    raise (newException(ValueError, "URL is too long"))
  return result

proc b64Str*(msg:string): string = 
  result = encode(msg,safe=true)
 
proc unb64str*(msg:string): string = 
  result = decode(msg)


proc returnC2PubKey(c2PrivKeyHexStr: string): Key =
  let c2PrivKey = parseHexStr(c2PrivKeyHexStr)
  var a: array[32, byte]; a[0..31] = c2privKey.toOpenArrayByte(0, 31)
  let c2PubKey = crypto_key_exchange_public_key(Key(a))
  return c2PubKey

proc writeStringToFile*(fileName: string, contents: string) =
  let f = open(filename, fmWrite)
  f.write(contents)
  defer: f.close()

proc readStringFromFile*(fileName: string): string =
  let f = open(filename, fmRead)
  defer: f.close()
  result = f.readAll()

proc createEmptyConfig(): StaticConfig =
  var config = StaticConfig()
  let id = $(genOid())
  config.buildID = id
  config.deploymentID = id
  config.killEpoch = 0
  config.interval = 0
  config.callback = '\0'.repeat(URL_MAX_LEN)
  return config

proc createEncConfig(config:StaticConfig): EncConfig =
  let configBytes = cast[seq[byte]](serConfig(config))
  let encConfig = new EncConfig
  let (priv,pub) = generateKeyPair()
  echo "DEBUG EncConfig priv:", priv
  echo "DEBUG EncConfig pub:", pub
  encConfig.privKey = priv
  encConfig.pubKey = pub 
  encConfig.encObj = enc(encConfig.privKey, encConfig.pubKey,configBytes)
  result = encConfig

proc readEncConfig*(encConfig:EncConfig): StaticConfig =
  let configBytes = dec(encConfig.privKey, encConfig.encObj)
  let config = desConfig(toString(configBytes))
  result = config

proc genOutFile(configIn:string,configOut:string)= 
  let configJSONStr = readStringFromFile(configIn)
  let configJSON = parseJson(configJSONStr)

  echo configJSON
  let newConfig = createEmptyConfig()
  newConfig.callback = padUrl(configJSON["callback"].getStr)
  let c2PubKey = returnC2PubKey(configJSON["c2PrivKey"].getStr)
  newConfig.c2PubKey = c2PubKey
  newConfig.killEpoch = int32(configJSON["killEpoch"].getInt)
  newConfig.interval = int32(configJSON["interval"].getInt)
  let encConfig = createEncConfig(newConfig)
  
  echo "EncConfig pubkey: ",encConfig.pubKey
  echo "EncConfig privkey: ",encConfig.privKey
  echo "EncConfig EncObj : ",encConfig.encObj
  
  let b64Str = b64Str(toFlatty(encConfig))
  writeStringToFile(configOut, b64Str)

when isMainModule:
  let dConfigOut = "debug.config"
  let dConfigIn = "debug.json"
  genOutFile(dConfigIn,dConfigOut)
