import argparse
from datetime import datetime, timezone
from hashlib import blake2b
from logger import *
import socket
import threading

banner = """
                                     .o8ooo8o
                                    "88'  `"'  `8888P
  888oooo.   888oooo.   ooo. .oo.    888oooo.  oooo d8b
  d88' `88b  d88' `88b  `888P"Y88b   888oooo.  888
  888   888  888   888   888   888   888       888oooo.
  888   888  888   888   888   888   888            888
  `V88V"V8P' `V88V"V8P' o888o o888o o888o     `Y8bod8P'
        .8'        .8'
 `Y8P'  8P  `Y8P'  8P  COPYRIGHT 2024 JSMASSMANN ET AL.
   `888""     `888""
"""

VERSION = "GGNFS Client Version 0.0"

parser = argparse.ArgumentParser(prog = "ggnfs-client", description = "A client program for the GGNFS.", add_help = False)

parser.add_argument("-h", action = "help", help = "Display this menu and exit.")
parser.add_argument("-v", action = "version", help = "Display the program's version and exit.", version = VERSION + ".")
parser.add_argument("-i", required = True, help = "The IP address or domain name of the server.", metavar = "ip", dest = "ip")
parser.add_argument("-n", required = True, help = "The name of the filesystem to access.", metavar = "name", dest = "name")
parser.add_argument("-s", action = "store_true", help = "Whether the GGNFS client should abort upon warnings.", dest = "safe")
parser.add_argument("-p", default = 43690, help = "What port the server runs on; default 43690.", metavar = "port", dest = "port")

args = parser.parse_args()

ip = args.ip
port = args.port

log_header("Connecting to remote", False)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((ip, port))

log_header("Successfully connected", False)

# Authenticating

log_header("Authenticating", False)

prelogin = 0

while True:
  data = server.recv(1024)
  if data == b"\x00":
    # Server's welcomed us. Let's ping it.
    n = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S").encode()
    nlen = hex(len(n))[2:]
    if len(nlen) % 2 == 1:
      nlen = "0" + nlen
    server.sendall(b"\x0f" + bytes.fromhex(nlen) + n)
  if data and data[0] == 15:
    le = data[1]
    time = int(data[2:2+le].hex(),16)
    print(f"\x1b[2;92mServer ping time: {time/1000:.3f} ms.")
    if time > 350000:
      print(f"This is a somewhat high ping time.\x1b[2;0m")
      abort = getyn("Abort connection")
      if abort == "y":
        server.close()
        sys.exit()
    # Tell the server which FS we wanna do work on
    server.sendall(b"\x55" + args.name.encode() + b"\x00")
    log_content(f"Requested to access filesystem {args.name}.", False)
  if data and data[0] == 129 and prelogin == 0:
    yn = input(f"\x1b[0;38;5;219mUsername: \x1b[0m")
    server.sendall(b"\x55" + yn.encode() + b"\x00")
    prelogin = 1
  elif data and data[0] == 129 and prelogin == 1:
    salt = data[1:]
    pwd = input(f"\x1b[0;38;5;213mPassword: \x1b[0m")
    server.sendall(b"\x55" + blake2b(salt + pwd.encode()).digest())
    prelogin = 2
  elif data and data[0] == 129:
    print(f"\x1b[0;38;5;115mSuccessfully logged in.\x1b[0m")
    break
  if data and data[0] == 170:
    errmsg = b""
    i = 1
    while data[i] != 0:
      a = hex(data[i])[2:]
      if len(a) < 2:
        a = "0"*(2-len(a)) + a
      errmsg += bytes.fromhex(a)
      i += 1
    errmsg = errmsg.decode()
    err(errmsg)

log_header("Successfully authenticated", False)
print("\n\n")

log(banner, 36, 96, "", "", False)