from logging import *
import os

def getdata(yn, pwdfile):
  try:
    fio = open(pwdfile, "rb")
    pwddata = fio.read()
    fio.close()
  except Exception:
    err(f"The file {pwdfile} could not be opened.")
  i = 0
  while True:
    cyn = b""
    while pwddata[i] != 0:
      a = hex(pwddata[i])[2:]
      if len(a) < 2:
        a = "0"*(2-len(a)) + a
      cyn += bytes.fromhex(a)
      i += 1
    if cyn == yn:
      break
    i += 69
    if i >= len(pwddata):
      return -1
  return (pwddata[i+1:i+5], pwddata[i+5:i+69])

def adddata(yn, salt, hash, pwdfile):
  try:
    fio = open(pwdfile, "ab")
    fio.write(yn + b"\x00" + salt + hash)
    fio.close()
  except Exception:
    error(f"The file {pwdfile} could not be opened.")