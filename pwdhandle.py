from logging import *
import os

def getdata(yn: bytes, pwdfile: str):
  try:
    fio = open(pwdfile, "rb")
    pwddata = fio.read()
    fio.close()
  except Exception:
    err(f"The file {pwdfile} could not be opened.")
  i = 0
  j = 1
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
    j += 1
  return (pwddata[i+1:i+5], pwddata[i+5:i+69], j)

def adddata(yn: bytes, salt: bytes, hash: bytes, pwdfile: str) -> None:
  try:
    fio = open(pwdfile, "ab")
    fio.write(yn + b"\x00" + salt + hash)
    fio.close()
  except Exception:
    error(f"The file {pwdfile} could not be opened.")