import os

# DHKE utils + simple KDF

# Safe DH modulus generated randomly at the time of writing

MODULUS = 24232007666983577952695034427041601357329402128532980921601037889731103189552283667752389112051837994860205423175088441226102811700144050799450463184000420101612655873895340771876127405619453008312365136990515353706081962813294854868705997169587638642267042713103469556138077229083886143141698612784454972441680588042407408723801591049508556631676913672916808506009933285333509229147931256789339496872393608363869131201224717172482254928897456276422352920768198089835215468002598365697134318853502914174986190729889745180366854379870466192366962635685019245992382890477065628255705399888515034153165534724367769970243

def isprime(n: int) -> bool: # Miller-Rabin test for primality of n.
  numbits = len(bin(n))-2
  if n == 2: return True
  if n % 2 == 0: return False
  r = 0
  s = n - 1
  while s % 2 == 0:
    r += 1
    s //= 2
  for j in range(128):
    a = (int.from_bytes(os.urandom(numbits), byteorder = "big")%(n-2))+2
    x = pow(a,s,n)
    if x == 1 or x == n-1:
      continue
    for j in range(r - 1):
      x = pow(x, 2, n)
      if x == n - 1:
        break
    else:
      return False
  return True

def issafe(p: int):
  return isprime(p) and isprime((p-1)//2)

def getPR(p: int):
  # Function for finding a primitive root mod a safe prime p.
  if not issafe(p):
    return None
  # We randomly test integers < p to see if they're primitive roots mod p; the probability is c. 1-1/q so we'll only need a few attempts.
  q = (p-1)//2
  while True:
    numbits = len(bin(p))-2
    u = (int.from_bytes(os.urandom(numbits), byteorder = "big")%(p-2))+2
    g = pow(u,int((p-1)/q),p)
    if g > 1: return g

# A simple KDF (2048 bits -> 256 bits), easier to implement than Argon2 etc.
# Hash-esque (just a bunch of arithmetic + shifts chosen at random).
# It only uses two hard-coded values, one for the default key and one for the initial internal state.

ctw = "59298769d3f62f6e1c6b4cb68e80d4e1e7ad190959027876d25ccea4f535328c5f62834fca93f3bb3e3f59e37692daee1ae74ea947da8175a5c7cab7316d6d649e12d189e9862eb35f36758d9930efcb1ab92e4087f185c7bd55cbff074f37185d3dc148c90a31303f7475fe8522ad88f414307e54388513d1380f62307363987bb7dcf2db650ccc6b7b6eb8af53dfa32f951e6c60e57ed0edd1dcbd0018581e6b9b943fd7c9fdd220f769fabb89ec52f740131e7f9d7b4ebb850b134b643a377474b1aac4e225752aac7cf9a26dd55eee782e7e4ce9b826af8eeb3616f163977a0bc9db183043315bb7591c9c54ea0b2b085b785423c637cf2318a827865fd2"
ctw = bytes.fromhex(ctw)

# Hex expansion of sqrt 5
a = "23c6ef372fe94f82be73980c0b9db906821044ed7e744e4a3f0d8d423a1831d2a4ecfe162a7a4f6fe068e08b6b7e304fe0310de125080600583ac97481e66bc6de0d5af5d2e2f0efd0b073addff7afb8cc9a64ba38a6e2d0595ba1999fbff77c2c4dc6771a096866377ee78f21b29ef3a8e389567da7b054bfd8a0ee0bc95cdcbce753723e7549b650f5c89e665d2474e79722c91c851d2eb46f03d603693b0ce9f42a10833c1d54807166a5b375a61e890b6e351dec88a541ba81b91971f345a98a29e36453b954445584d1d2ccdc950cced228bebeb10153a159a773d18d05e9f02064157d728069ce1e42c1180c35638395de3d7b9df78e4269d9e0ddb057"
A = list(bytes.fromhex(a))
sqrt5 = [A[j:j+16] for j in range(0,len(A),16)]

def rotate(l, n: int):
  return l[-n:] + l[:-n]

def kdf(shsec: bytes, key: bytes = ctw):
  L = sqrt5
  M = []
  X = list(shsec)
  K = list(key)
  if len(K) != 256:
    return -1
  for j in range(sum(list(X))%32+32):
    K = [(K[i]^(L[i%16][i%16]<<1))%256 for i in range(256)]
    L = [rotate(L[i], L[i][0]%32-16) for i in range(16)]
    for i in range(32):
      a, b = K[i]%16, K[i+32]%16
      L[0][a], L[0][b] = L[0][b], L[0][a]
    if j % 3 != 2:
      for i in range(16):
        for k in range(16):
          L[i][k] += X[k]
          L[i][k] ^= (X[k]^(X[k]<<1))
          L[i][k] %= 256
      X = rotate(X, -16)
    K = rotate(K,K[0]%64)
  return b"".join([bytes(L[k])[:8] for k in [0,7,14,15]])

# Roll-my-own AES!
# Nb = 4, Nk = 8, Nr = 14.
# Currently broken, and I don't have the patience to fix it.

a = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
A = list(bytes.fromhex(a))
Sbox = [A[j:j+16] for j in range(0,len(A),16)]

def subbytes(inp: list[list[int]]) -> list[list[int]]:
  out = inp
  for i in range(4):
    for j in range(4):
      a = inp[i][j]
      out[i][j] = Sbox[a//16][a%16]
  return out

def shiftrows(inp: list[list[int]]) -> list[list[int]]:
  rows = [[inp[j][i] for j in range(4)] for i in range(4)]
  for i in range(4):
    rows[i] = rows[i][i:] + rows[i][:i]
  return [[rows[j][i] for j in range(4)] for i in range(4)]

def xtimes(byt: int) -> int:
  if byt < 128:
    return byt*2
  return ((byt*2)%256)^27

def o03(byt: int) -> int:
  return byt^xtimes(byt)

def o09(byt: int) -> int:
  return byt^xtimes(xtimes(xtimes(byt)))

def o0b(byt: int) -> int:
  return o09(byt)^xtimes(byt)

def o0d(byt: int) -> int:
  return o09(byt)^xtimes(xtimes(byt))

def o0e(byt: int) -> int:
  return xtimes(byt)^o03(xtimes(xtimes(byt)))

def mixcolumns(inp: list[list[int]]) -> list[list[int]]:
  out = inp
  for i in range(4):
    out[i][0] = xtimes(inp[i][0])^o03(inp[i][1])^inp[i][2]^inp[i][3]
    out[i][1] = inp[i][0]^xtimes(inp[i][1])^o03(inp[i][2])^inp[i][3]
    out[i][2] = inp[i][0]^inp[i][1]^xtimes(inp[i][2])^o03(inp[i][3])
    out[i][3] = o03(inp[i][0])^inp[i][1]^inp[i][2]^xtimes(inp[i][3])
  return out

def addroundkey(inp: list[list[int]], roundkey: bytes) -> list[list[int]]:
  out = inp
  for i in range(4):
    for j in range(4):
      out[i][j] ^= roundkey[4*i+j]
  return out

def cipher(inp: bytes, key_sched: bytes) -> bytes:
  # Performs 14 rounds on a given internal state with a 240-byte key schedule.
  # First, convert the 128-bit input into a 4x4 matrix of bytes.
  # N.B!!!!! Every element of state is a column, not a row.
  M = []
  for i in range(16):
    if i % 4 == 0:
      M.append([])
    M[-1].append(inp[i])
  state = M[:]
  state = addroundkey(state, key_sched[:16])
  for i in range(14):
    state = subbytes(state)
    state = shiftrows(state)
    if i < 13:
      state = mixcolumns(state)
    state = addroundkey(state, key_sched[16*(i+1):16*(i+2)])
  return b"".join([bytes(state[k]) for k in range(4)])

a = "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
A = list(bytes.fromhex(a))
invSbox = [A[j:j+16] for j in range(0,len(A),16)]

def invmixcolumns(inp: list[list[int]]) -> list[list[int]]:
  # Forgive me, God
  out = inp
  for i in range(4):
    out[i][0] = o0e(inp[i][0])^o0b(inp[i][1])^o0d(inp[i][2])^o09(inp[i][3])
    out[i][1] = o09(inp[i][0])^o0e(inp[i][1])^o0b(inp[i][2])^o0d(inp[i][3])
    out[i][2] = o0d(inp[i][0])^o09(inp[i][1])^o0e(inp[i][2])^o0b(inp[i][3])
    out[i][3] = o0b(inp[i][0])^o0d(inp[i][1])^o09(inp[i][2])^o0e(inp[i][3])
  return out

def invshiftrows(inp: list[list[int]]) -> list[list[int]]:
  rows = [[inp[j][i] for j in range(4)] for i in range(4)]
  for i in range(4):
    rows[i] = rows[i][-i:] + rows[i][:-i]
  return [[rows[j][i] for j in range(4)] for i in range(4)]

def invsubbytes(inp: list[list[int]]) -> list[list[int]]:
  out = inp
  for i in range(4):
    for j in range(4):
      a = inp[i][j]
      out[i][j] = invSbox[a//16][a%16]
  return out

def invcipher(inp: bytes, key_sched: bytes) -> bytes:
  # Undoes 14 rounds on a given ciphertext with a 240-byte key schedule.
  M = []
  for i in range(16):
    if i % 4 == 0:
      M.append([])
    M[-1].append(inp[i])
  state = M[:]
  for i in range(14)[::-1]:
    state = addroundkey(state, key_sched[16*(i+1):16*(i+2)])
    if i < 13:
      state = invmixcolumns(state)
    state = invshiftrows(state)
    state = invsubbytes(state)
  state = addroundkey(state, key_sched[:16])
  return b"".join([bytes(state[k]) for k in range(4)])

RCV = [b"\x01", b"\x02", b"\x04", b"\x08", b"\x10", b"\x20", b"\x40", b"\x80", b"\x1b", b"\x36"]
Rcon = [k + b"\x00\x00\x00" for k in RCV]

def rotword(word: bytes) -> bytes:
  return word[1:] + word[:1]

def subword(word: bytes) -> bytes:
  wordvals = list(word)
  for i in range(4):
    a = wordvals[i]
    wordvals[i] = Sbox[a//16][a%16]
  return bytes(wordvals)

def xor(word1: bytes, word2: bytes) -> bytes:
  word1vals = list(word1)
  word2vals = list(word2)
  out = [0]*4
  for i in range(4):
    out[i] = word1vals[i]^word2vals[i]
  return bytes(out)

def keyexpansion(key: bytes) -> bytes:
  # Turns a 32-byte key into a 240-byte key schedule
  w = [key[4*i:4*i+4] for i in range(8)] + [b"\x00\x00\x00\x00"]*52
  for i in range(8, 60):
    temp = w[i-1]
    if i % 8 == 0:
      temp = xor(subword(rotword(temp)), Rcon[i//8])
    elif i % 8 == 4:
      temp = subword(temp)
    w[i] = xor(w[i-8], temp)
  return b"".join(w)

def encrypt(pt: bytes, key: bytes) -> bytes:
  key_sched = keyexpansion(key)
  # CBC
  a = len(pt)//16+1
  if len(pt)%16 == 0:
    a -= 1
  outblocks = [b"\x00"*16]*a
  for i in range(a):
    inblock = pt[16*i:16*(i+1)]
    if i == 0:
      outblock = cipher(inblock, key_sched)
    else:
      outblock = cipher(xor(inblock, outblocks[-1]), key_sched)
    outblocks[i] = outblock
  return b"".join(outblocks)

def decrypt(ct: bytes, key: bytes) -> bytes:
  key_sched = keyexpansion(key)
  a = len(ct)//16+1
  if len(ct)%16 == 0:
    a -= 1
  outblocks = [b"\x00"*16]*a
  for i in range(a):
    inblock = ct[16*i:16*(i+1)]
    if i == 0:
      outblock = invcipher(inblock, key_sched)
    else:
      outblock = xor(invcipher(inblock, key_sched), inblocks[-1])
    outblocks[i] = outblock
  return b"".join(outblocks)