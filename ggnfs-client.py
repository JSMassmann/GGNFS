import argparse
from datetime import datetime, timezone
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
 `Y8P'  8P  `Y8P'  8P  COPYRIGHT 2024 JSMASSMANN ET AL
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

log(banner, 36, 96, "", "", False)
while True:
  pass