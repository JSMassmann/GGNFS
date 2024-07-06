Note that all values below are big-endian.

A GGNFS is laid out as a quite simple tree. GGNFS has support for journaling, which is crucial when many clients are connected. An FS identifier, FS metadata and the journal are contained in sectors 0 - 40835 (i.e. the first 20 MiB of the disk image; values in parentheses are lengths in bytes):

Magic bytes (12) - `0x564F50536F61A2856E46CD51`.
No. of used sectors (8).
Journal (20907648).
Padding (352) - nulls.
Magic bytes (12) - `0x7F6E46738438C47A674649FB`.

Each sector after sector 15 starts with 16 bytes of identification (so it actually only contains 496 bytes of information). These are:

- Primary sector type (1):
  - `0x00` if this sector is unused.
  - `0x0F` if it is the metadata of a directory.
  - `0xF0` if it contains the contents of a file as opposed to information about it.
  - `0xFF` if it is the metadata of a file.
- Secondary sector type (1):
  - `0x00` if this sector is the data or metadata of a leaf (file or empty directory).
  - `0x80` else (i.e. if the primary sector type is `0x0F` and the directory is nonempty).
- Primary extra information (6):
  - A signed 48-bit integer describing the offset of the next sector of the file, if the primary sector type is `0xF0` and this is not the final sector of that file.
  - `0x000000000000` else.
- Secondary extra information (8):
  - A signed 64-bit integer describing the offset of the next sector of the metadata, if the primary sector type is `0x0F` or `0xFF` and e.g. the name is long.
  - `0x000000000000` else.

Directory metadata after the first 16 bytes:

- Offset of parent directory's metadata (6) - `0xFFFFFFFFFFFF` for root directory.
- Directory name (<= 65,535), null-terminated.
- Amount of (real) subdirectories (2) - mainly used as a consistency check
- Amount of files (3) - mainly used as a consistency check
- Who owns the directory (2) - each user is represented by a UID. Superuser is 0.
- How many people can edit it, other than the superuser (2)
- Who can edit it, other than the superuser (<= 131,070)
- How many people can view it, other than the superuser (2)
- Who can view it, other than the superuser (<= 131,070)

File metadata after the first 16 bytes:

- Offset of parent directory's metadata (6)
- Name of file (<= 65,535), null-terminated.
- Who owns the file (2)
- How many people can edit it (2)
- Who can edit it (<= 131,070)
- How many people can view it (2)
- Who can view it (<= 131,070)
- When the file was most recently edited (5)
- Length of the file (6) - mainly used to determine how much padding there is on the last sector
- Offset of the first sector of the file (6)

In both cases, the metadata is then followed by nulls if any space remains. File and directory names are encoded in UTF-8, cannot contain nulls or forward slashes, and cannot be `.` or `..`.

The journal format is as follows:

Each journal entry is 10 bytes or more. Each journal entry contains:

- Length of the journal entry (2).
- Operation type (1):
  - `0x00` for retrieving metadata.
  - `0x0F` for reading a file into memory.
  - `0x55` for creating a file.
  - `0x7E` for editing a file.
  - `0x81` for deleting a file.
  - `0xAA` for modifying metadata.
  - `0xF0` for creating a directory.
  - `0xFF` for deleting a directory.
- Operation data (variable):
  - For operation type `0x00`, this is the path to the file or directory, separated with slashes and null-terminated.
  - For operation type `0x0F`, this is the path, followed by 8 bytes of the RAM address where the file buffer begins, followed by 6 bytes of how many bytes should be read.
  - For operation type `0x55`, this is the path to the file's parent directory.
  - Operation type `0x7E` is analogous to `0x0F`, but where we write from rather than to the buffer. Note that the GGNFS server will automatically update the file's length metadata.
  - Operation type `0x81` is analogous to `0x55`.
  - For operation type `0xAA`, this is the path to the file or directory, followed by 1 byte of the metadata entry to be modified and then the new value of the metadata. Note that the GGNFS server will automatically update the count of editors/viewers, only the list needs to be provided. The encodings of metadata entries are:
    - `0x00` for parent directory (for moving).
    - `0x0F` for name.
    - `0x7E` for owner.
    - `0xF0` for editors.
    - `0xFF` for viewers.
  - Operation types `0xF0` and `0xFF` are analogous to `0x55` and `0x81`.

The operation types were chosen to be memorable hex values with sufficiently large Hamming distances from each other.

The CGNFS server by default listens on port `0xAAAA` (43690). The protocol for client-server communication is as follows:

Each packet's first byte determines what kind of packet it is:

- `0x00` for a welcome.
- `0x0F` for a ping or pong.
- `0x55` for command data.
- `0x7E` for a confirmation request.
- `0x81` for a confirmation.
- `0xAA` for a cancellation or error.
- `0xF0` for a command.
- `0xFF` for a goodbye.

The client-server connection begins with a handshake which is used to verify that the connection is reliable and not excessively latent:

- The server sends a welcome packet to the client.
- The client pings the server, including the UTC timestamp in the packet content.
- The server responds with a pong, containing its UTC timestamp.

If the server took too long to respond, the client may simply disconnect without following the goodbye protocol. Else:

- The client sends a packet of type `0x55`, containing a null-terminated string of the name of the GGNFS to connect to.

If the server is not serving a filesystem with that name, it will respond with a packet of type `0xAA`. Else, it sends `0x81`.

Next, authentication is performed.

To log in to their account:

- The client sends a packet of type `0x55`, containing their username on that filesystem. N.b. the username/password data is stored separately to the filesystem image.
- If that username exists, the server responds with a packet of type `0x81` containing the random salt data for that user in the passwords file, else `0xAA`, in which case the process repeats (or the user can disconnect following the disconnection protocol).
- The client then sends a packet of type `0x55`, containing the hash of their password prepended by the random salt data.
- The server compares that hash with the hash stored in the passwords file. If it matches, the server sends a packet of tpye `0x81`, else `0xAA`, in which case the client is prompted again.

To create an account, a similar protocol to above is followed:

- The client sends a packet of type `0x55`, containing their username on that filesystem.
- If that username already exists or the server is not currently accepting new sign-ups, the server responds with a packet of type `0xAA` (possibly including extra error information), in which case the client chooses a new username or aborts, else `0x81`.
- The server then sends a packet of type `0x55` containing some newly randomly generated salt data for that user.
- The client then sends a packet of type `0x55`, containing the hash of their password prepended by the random salt data.
- The server stores the username, salt and hash in its passwords file.

After a successful log-in or sign-up, the server stores the UID of that user (where UIDs are just generated in chronological user, i.e. the first non-superuser account to be created is 1). The client can then communicate requests it desires to make, where each request is simply a packet of type `0xF0` with second byte the operation type, followed by a packet of type `0x55` containing the operation data. 

The server checks if that UID has sufficient privileges and if there are no locks on the requested resource (e.g. another user is currently editing), and if not it adds it to its journal and another server thread will later perform it, after which the server sends an `0x81` or `0xAA`.

For deletions, renames and metadata modifications, the server will also issue a confirmation to the client, and upon a client sending a packet of type `0xAA` it will abort.