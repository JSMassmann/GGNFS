GGNFS stands for "GGNFS is a Good Network File System". This provides both a server and client interface.

This server utilizes heavy multithreading! We have n+m+1 threads, where n is the amount of concurrent filesystems and m the amount of concurrent clients:

- 1 thread is to await client connections and perform authentication.
- n threads are to perform requested changes by clients to filesystems.
- m threads are to await change requests by clients.

Therefore a server would be able to act upon, say, 100 filesystems for 100 concurrent clients. A server can handle up to 65,536 distinct users with custom read/write permissions for each.

The client's interface is a simple shell which in the future may have scripting support.

All traffic is encrypted, with Diffie-Hellman key exchange performed after authentication. We always use a precomputed modulus around `2.4232 * 10^29` as it is a hassle to generate safe primes on-the-fly and DH is not less secure when moduli are reused.

TODO: Encrypt all traffic.