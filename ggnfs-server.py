import argparse
from datetime import datetime, timezone
from logger import *
from pwdhandle import *
import socket
import threading

VERSION = "GGNFS Server Version 0.0"

parser = argparse.ArgumentParser(prog = "ggnfs-server", description = "A server program for the GGNFS.", add_help = False)

parser.add_argument("-h", action = "help", help = "Display this menu and exit.")
parser.add_argument("-v", action = "version", help = "Display the program's version and exit.", version = VERSION + ".")
parser.add_argument("-l", nargs = "+", required = True, help = "The files to store the server logs.", metavar = "logs", dest = "logfiles")
parser.add_argument("-f", nargs = "+", required = True, help = "The filesystem images for clients to edit.", metavar = "imgs", dest = "fs")
parser.add_argument("-n", nargs = "+", required = True, help = "The names of the corresponding filesystems.", metavar = "names", dest = "names")
parser.add_argument("-P", nargs = "+", required = True, help = "The password files for corresponding filesystems.", metavar = "pwds", dest = "pwds")
parser.add_argument("-s", action = "store_true", help = "Whether the GGNFS server should abort upon warnings.", dest = "safe")
parser.add_argument("-q", action = "store_true", help = "Whether the GGNFS server shouldn't print logs to the screen.", dest = "quiet")
parser.add_argument("-p", default = 43690, help = "What port the server should run on; default 43690.", dest = "port", type = int)

args = parser.parse_args()

mlf = args.logfiles[0]
names = args.names
pwds = args.pwds
quiet = args.quiet
port = args.port

if len(args.logfiles) != len(args.fs)+1 or len(args.logfiles) != len(names)+1:
  err(f"There must be one more logfile than filesystems, as the first logfile is used for storing logs for the server itself.", mlf)
if len(args.fs) != len(names):
  err(f"There must be as many filesystem images as filesystem names so that the server knows which filesystem image to perform actions on.", mlf)
if len(args.fs) != len(args.pwds):
  err(f"There must be as many filesystem images as password files so that the server knows which passwords to use.", mlf)
if len(names) != len(set(names)):
  err(f"Filesystem names must be unique.", mlf)

sip = socket.gethostbyname(socket.gethostname())

log_header("Testing disk image integrity", quiet, mlf)

ggnfs_m1 = b"VOPSoa\xa2\x85nF\xcdQ"
ggnfs_m2 = b"\x7fnFs\x848\xc4zgFI\xfb"

for k in range(len(args.fs)):
  try:
    fio = open(args.fs[k], "rb")
    imgcontent = fio.read(20908032)
    fio.close()
  except Exception:
    err(f"The file {args.fs[k]} could not be opened.", mlf, args.logfiles[k+1])
  if imgcontent[:12] != ggnfs_m1 or imgcontent[20908020:] != ggnfs_m2:
    err(f"The disk image {args.fs[k]} has invalid magic bytes.", mlf, args.logfiles[k+1])
  if imgcontent[20907668:20908020] != b"\x00"*352:
    err(f"The disk image {args.fs[k]} has invalid padding.", mlf, args.logfiles[k+1])
  log_content(f"The disk image {args.fs[k]} has correct padding and magic bytes. It may, however, still be corrupt.", quiet, mlf, args.logfiles[k+1])

log_header("All disk images correct", quiet, mlf)

log_header("Initializing GGNFS server", quiet, mlf)

client_sockets = []
client_addrs = []
client_uids = []
client_fs = []
client_yns = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("", port))
server.listen()

log_content(f"Listening on {sip}:{port}.", quiet, mlf)

for k in range(len(args.fs)):
  dt = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")
  log_content(f"Filesystem {names[k]}, mounted at {args.fs[k]}, online at {dt} UTC.", quiet, mlf, args.logfiles[k+1])

log_header("Server initialized", quiet, mlf)
log_header("Awaiting client requests", quiet, mlf)

def authenticate(clientnum):
  global client_sockets, client_uids, client_fs
  client = client_sockets[clientnum]
  ip = client_addrs[clientnum][0]
  port = client_addrs[clientnum][1]

  prelogin = 0
  
  client.sendall(b"\x00") # Welcome!
  while True:
    data = client.recv(1024)
    if data and data[0] == 15:
      le = data[1]
      time = datetime.strptime(data[2:2+le].decode(),"%Y-%m-%d %H:%M:%S")
      log_content(f"Client #{clientnum} has pinged at {time}.", quiet, mlf)
      td = datetime.now(timezone.utc).replace(tzinfo = None) - time
      ncont = hex(int((td*1000000).total_seconds()))[2:]
      if len(ncont) % 2 == 1:
        ncont = "0" + ncont
      nlen = hex(len(ncont)//2)[2:]
      if len(nlen) % 2 == 1:
        nlen = "0" + nlen
      client.sendall(b"\x0f" + bytes.fromhex(nlen) + bytes.fromhex(ncont))
    elif data and data[0] == 85 and prelogin < 2:
      # 0x55 has a different meaning before login than during.
      req = b""
      i = 1
      while data[i] != 0:
        a = hex(data[i])[2:]
        if len(a) < 2:
          a = "0"*(2-len(a)) + a
        req += bytes.fromhex(a)
        i += 1
      req = req.decode()
      if prelogin == 0:
        if req not in names:
          client.sendall(b"\xaa" + f"The filesystem {req} does not exist.".encode() + b"\x00")
          client.shutdown(socket.SHUT_RDWR)
          client.close()
          break
        else:
          client.sendall(b"\x81")
          prelogin = 1
          client_fs[clientnum] = names.index(req)
      else:
        pwdfile = pwds[client_fs[clientnum]]
        result = getdata(req.encode(), pwdfile)
        log_content(f"Client #{clientnum} requests to log in with username {req} to filesystem {names[client_fs[clientnum]]}, with password file {pwdfile}.", quiet, mlf)
        if result == -1:
          client.sendall(b"\xaa" + f"The username {req} does not exist.".encode() + b"\x00")
          client.shutdown(socket.SHUT_RDWR)
          client.close()
          break
        else:
          client.sendall(b"\x81" + result[0])
          client_yns[clientnum] = req.encode()
          prelogin = 2
    elif data and data[0] == 85:
      # This packet contains the hash of the user's password
      req = client_yns[clientnum]
      result = getdata(req, pwds[client_fs[clientnum]])
      if data[1:] == result[1]:
        client.sendall(b"\x81")
        log_content(f"Client #{clientnum} successfully logged in to username {req.decode()}.", quiet, mlf)
      else:
        client.sendall(b"\xaa" + f"That password is incorrect.".encode() + b"\x00")
        client.shutdown(socket.SHUT_RDWR)
        client.close()
        break
def waitinput(clientnum):
  # Thread to read client requests and add these commands to respective journals
  pass

def waitoutput(fsid):
  # Thread to read from journals and perform the requested operations
  pass

while True:
  # Main thread, awaiting client connections and authenticating
  nclnm = len(client_sockets)
  (client, addr) = server.accept()
  dt = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")
  log_content(f"Connected by {addr[0]}:{addr[1]}.", quiet, mlf)
  log_content(f"Client #{nclnm} connected to server at {dt}.", quiet, mlf)
  client_sockets.append(client)
  client_addrs.append(addr)
  client_uids.append(None)
  client_fs.append(None)
  client_yns.append(None)
  t = threading.Thread(target=authenticate,args=[nclnm])
  t.start()