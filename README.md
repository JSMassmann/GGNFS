GGNFS stands for "GGNFS is a Good Network File System". This provides both a server and client interface.

This server utilizes heavy multithreading! We have n+m+1 threads, where n is the amount of concurrently active filesystems and m the amount of concurrent clients:

- 1 thread is to await client connections and perform authentication.
- n threads are to perform requested changes by clients to filesystems.
- m threads are to await change requests by clients.

Therefore a server would be able to act upon, say, 100 filesystems for 100 concurrent clients. A server can handle up to 65,536 distinct users with custom read/write permissions for each.

The client's interface is a simple shell which in the future may have scripting support.

All traffic is encrypted, with Diffie-Hellman key exchange performed after authentication. We always use a precomputed modulus around `2.4232 * 10^29` as it is a hassle to generate safe primes on-the-fly and DH is not less secure when moduli are reused.

TODO: Signing-up and listing available filesystems. Fix AES in order to actually encrypt stuff.

For disk partitioning via GPT, the following GUIDs identify GGNFS filesystems:

- Userland GGNFS partition: `CD0F340E-81B8-F4C1-54FB-ABD0DFAEF7DA`.
- GGNFS partition for diskless booting: `F933D433-97FC-D0E6-404E-A02D2FA77986`.
- GGNFS partition for an ordinary OS: `CA87303B-6606-B777-4531-A7AE0BF8CAE0`.
- A temporary or encrypted GGNFS partition: `D6D7E74E-673B-0D16-C40E-8EDAF6888A08`.