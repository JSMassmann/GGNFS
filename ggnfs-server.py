import argparse
from datetime import datetime, timezone
from logger import *
import socket
import threading

VERSION = "GGNFS Server Version 0.0"

parser = argparse.ArgumentParser(prog = "ggnfs-server", description = "A server program for the GGNFS.", add_help = False)

parser.add_argument("-h", action = "help", help = "Display this menu and exit.")
parser.add_argument("-v", action = "version", help = "Display the program's version and exit.", version = VERSION + ".")
parser.add_argument("-l", nargs = "+", required = True, help = "The files to store the server logs.", metavar = "logs", dest = "logfiles")
parser.add_argument("-f", nargs = "+", required = True, help = "The filesystem images for clients to edit.", metavar = "imgs", dest = "fs")
parser.add_argument("-n", nargs = "+", required = True, help = "The names of the corresponding filesystems.", metavar = "names", dest = "names")
parser.add_argument("-s", action = "store_true", help = "Whether the GGNFS server should abort upon warnings.", dest = "safe")
parser.add_argument("-q", action = "store_true", help = "Whether the GGNFS server shouldn't print logs to the screen.", dest = "quiet")
parser.add_argument("-p", default = 43690, help = "What port the server should run on; default 43690.", dest = "port")

args = parser.parse_args()

mlf = args.logfiles[0]
quiet = args.quiet
port = args.port

if len(args.logfiles) != len(args.fs)+1 or len(args.logfiles) != len(args.names)+1:
  error(f"There must be one more logfile than filesystems, as the first logfile is used for storing logs for the server itself.", mlf)
if len(args.fs) != len(args.names):
  error(f"There must be as many filesystem images as filesystem names so that the server knows which filesystem image to perform actions on.", mlf)

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
    error(f"The file {args.fs[k]} could not be opened.", mlf, args.logfiles[k+1])
  if imgcontent[:12] != ggnfs_m1 or imgcontent[20908020:] != ggnfs_m2:
    error(f"The disk image {args.fs[k]} has invalid magic bytes.", mlf, args.logfiles[k+1])
  if imgcontent[20907668:20908020] != b"\x00"*352:
    error(f"The disk image {args.fs[k]} has invalid padding.", mlf, args.logfiles[k+1])
  log_content(f"The disk image {args.fs[k]} has correct padding and magic bytes. It may, however, still be corrupt.", quiet, mlf, args.logfiles[k+1])

log_header("All disk images correct", quiet, mlf)

log_header("Initializing GGNFS server", quiet, mlf)

client_ips = []
client_ports = []
client_uids = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(port)
server.bind(("", port))
server.listen()

log_content(f"Listening on {sip}:{port}.", quiet, mlf)

for k in range(len(args.fs)):
  dt = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")
  log_content(f"Filesystem {args.names[k]}, mounted at {args.fs[k]}, online at {dt} UTC.", quiet, mlf, args.logfiles[k+1])

def authenticate(clientnum):
  pass

while True:
  nclnm = len(client_ips)
  (client, addr) = server.accept()
  dt = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")
  log_content(f"Connected by {addr[0]}:{addr[1]}.", quiet, mlf)
  log_content(f"Client #{nclnm} connected to server at {dt}.", quiet, mlf)
  client_ips.append(addr[0])
  client_ports.append(addr[1])
  client_uids.append(None)
  t = threading.Thread(target=authenticate,args=[nclnm])
  t.start()