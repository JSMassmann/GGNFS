import argparse
from datetime import datetime, timezone
from logger import *
import socket
import threading

VERSION = "GGNFS Server Version 0.0"

parser = argparse.ArgumentParser(prog = "ggnfs-server", description = "A server program for the GGNFS.", add_help = False)

parser.add_argument("-h", action = "help", help = "Display this menu and exit.")
parser.add_argument("-v", action = "version", help = "Display the program's version and exit.", version = VERSION + ".")
parser.add_argument("-l", dest = "logfiles", help = "The files to store the server logs.", metavar = "logs", nargs = "+", required = True)
parser.add_argument("-f", dest = "fs", help = "The filesystem images for clients to edit.", metavar = "imgs", nargs = "+", required = True)
parser.add_argument("-n", dest = "names", help = "The names of the corresponding filesystems.", metavar = "names", nargs = "+", required = True)
parser.add_argument("-s", action = "store_true", dest = "safe", help = "Whether the GGNFS server should abort upon warnings.")
parser.add_argument("-q", action = "store_true", dest = "quiet", help = "Whether the GGNFS server shouldn't print logs to the screen.")

args = parser.parse_args()

mlf = args.logfiles[0]
quiet = args.quiet

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
log_content(f"Listening on {sip}:43690.", quiet, mlf)

for k in range(len(args.fs)):
  dt = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")
  log_content(f"Filesystem {args.names[k]}, mounted at {args.fs[k]}, online at {dt} UTC.", quiet, mlf, args.logfiles[k+1])