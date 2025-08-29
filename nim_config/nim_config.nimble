# Package

version       = "0.1.0"
author        = "Hortinstein"
description   = "Onimgiri is a simple beacon that talks to a web server"
license       = "MIT"

srcDir        = "src"
binDir        = "bin"

installExt    = @["nim"]
bin           = @["config", "test_python_config", "simple_test_python_config"]

# Dependencies
requires "enkodo >= 0.1.5"
requires "flatty"
requires "jsutils"
requires "monocypher"
requires "nim >= 1.6.10"
requires "oshostname >= 0.1.0"
requires "print"
requires "printdebug"
requires "psutil"
requires "puppy"
requires "urlly"

task buildall, "Build the package":
  exec "nimble build config"
  exec "./bin/config"

task test_python, "Test reading Python-generated config":
  exec "nimble build test_python_config"
  exec "./bin/test_python_config"

task simple_test, "Simple test reading Python-generated config":
  exec "nimble build simple_test_python_config"
  exec "./bin/simple_test_python_config"
