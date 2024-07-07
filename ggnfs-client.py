import argparse
from crypto import *
from datetime import datetime, timezone
from hashlib import blake2b
from logger import *
import os
import socket
import threading

# Cryptography

dh_shsecret = None
currentPR = None

# Main program

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
  if data and data[0] == 85:
    # This packet contains a Diffie-Hellman g^b.
    G = currentPR
    a = int.from_bytes(os.urandom(257), byteorder = "big")%MODULUS
    A = pow(G, a, MODULUS)
    A = hex(A)[2:]
    if len(A) % 2 != 0:
      A = "0" + A
    A = bytes.fromhex(A)
    server.sendall(b"\x55" + A)
    B = int(data[1:].hex(), 16)
    s = pow(B, a, MODULUS)
    # Convert this into a usable AES-256 key
    s = hex(s)[2:]
    if len(s) < 512:
      s = "0"*(512-len(s)) + s
    s = bytes.fromhex(s)
    s = kdf(s)
    dh_shsecret = s
    break
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
    # Diffie-Hellman time!
    G = getPR(MODULUS)
    currentPR = G
    print(f"\x1b[0;38;5;141mRequesting to perform Diffie-Hellman key exchange with primitive root {str(G)[:5]}...{str(G)[-5:]}.\x1b[0m")
    G = hex(G)[2:]
    if len(G) % 2 != 0:
      G = "0" + G
    G = bytes.fromhex(G)
    server.sendall(b"\x55" + G)
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

cmds = {
  "help": "Prints this menu or information about a specific command.",
  "exit": "Closes the connection with the server.",
  "info": "Prints information about a directory.",
  "chattrs": "Changes attributes of a directory or file.",
  "copy": "Copy a file to another directory.",
  "link": "Creates a hard link to a directory or file.",
  "list": "Lists the files in a directory, or prints information about a file.",
  "move": "Renames a file and/or moves it to another directory.",
  "touch": "Creates a file or updates an existing file's timestamps.",
  "cat": "Appends the contents of one file to another.",
  "read": "Prints the contents of a file or moves them to a local file.",
  "mkdir": "Creates a directory.",
  "delete": "Deletes a file or directory.",
  "write": "Writes to a file or replaces its contents with a local file.",
  "unlink": "Removes a hard link."
}

cmdargs = {
  "help": "  command Optional. The command to display help for.",
  "exit": "",
  "info": "  dir The directory to print information about.",
  "chattrs": "  path The directory or file to act on.\n  attr The attribute to modify.\n  val The new value of the attribute.",
  "copy": "  source The path to the original file.\n  dest   The destination directory path and new file name.",
  "link": "  source The path to the original file or directory.\n  dest The path and name of the link.",
  "list": "  path The path to the file or directory.",
  "move": "  source The path to the original file.\n  dest   The destination directory.",
  "touch": "  file The file to touch.",
  "cat": "  if The file to append from.\n  of The file to append to.",
  "read": "  if The file to read.\n  of Optional, the local file to read to (stdout if unspecified).",
  "mkdir": "  dir The path to the new directory and its name.",
  "delete": "  path The path to the file or directory to be deleted.",
  "write": "  of The file to write to.\n  if Optional, the local file to write from (stdin if unspecified).",
  "unlink": "  path The path to the link which should be removed."
}

while True:
  inp = input(f"{yn}@{args.name} $ ")
  cmd = inp.split(" ")[0]
  data = inp.split(" ")[1:]
  if cmd == "help":
    if data == []:
      l = max([len(i) for i in cmds.keys()])
      for i in sorted(cmds.keys()):
          print(i.ljust(l), cmds[i])
    elif data[0] in cmds:
      binfo = f"{data[0]}\n\n{cmds[data[0]]}"
      if cmdargs[data[0]] == "":
        print(binfo)
      else:
          print(binfo+f"\n\nArguments:\n{cmdargs[data[0]]}")
    else:
      warn(f"The command {data[0]} does not exist.", False)
  elif cmd == "exit":
    print("\x1b[0;38;5;98mClosing connection.\x1b[0m")
    break

server.shutdown(socket.SHUT_RDWR)
server.close()