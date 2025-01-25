# Setup a secure channel between a client and an enclave #

This is a Rust-based implementation of setting up a secure channel
between two end points using Diffie-Hellman key exchange and AES
encryption. This is used as a basis for the VECTOR project
demonstrator that is using Rust-based keystone Enclave runtime
environment. The demonstrator is setting up a connection from a remote
client to the enclave application.

Software is organized as the following components:

* **schannel-client** - Secure channel client thta is used to conect to
  the service.

* **schannel-eapp** - Enclave application.

* **schannel-host** - Secure channel host application that serves connecting
  clients and passes requests to the enclave application.

* **schannel-lib** - Shared code betwwen schannel-client and schannel-host.

The code implements the similar use case as the Keystone demo. The
client is sending a text line via the secure channel and the enclave
code is calculating the number of words in the text line and is
returning the result using the secure channel.

## Building ##

### Pre-conditions ###

Rust software development tools must be installed

* rustc - Rust compiler
* cargo - Rusts's package manager

Keystone must be installed and built. The environment variable
*KEYSTONE_BUILD_DIR* should point to the build directory (e.g.,
build-generic64 for qemu builds) of the Keystone installation.

A Rust SDK for building Keystone enclave applications should be
cloned:

      git clone https://github.com/vector-sdk/rust-sdk

Library static-dh-ecdh should be cloned:

      git clone https://github.com/vector-sdk/static-dh-ecdh

### Compilation ###

The project includes a makefile and compilation is triggered by using
a command:

      make

This command builds all subdirectories and installs executables to the
target subdirectory. It is possible to remove compiled files using a
command:

      make clean

The makefile is using cargo tool for building.

### Installation ###

Compiled files should be installed into qemu-based Keystone
demonstrator. This can be done using a command:

      make install

The executables and installed into root file system and new image is
built.

## Running the demo ##

The demo is similar to the original keystone-demo. Server and client
programs are started and a secure channel is established between these
processes. You can write a text line in a client console. The text
line is then transferred to the server via the secure channel. The
server calculates the number of words in the line and returns the
result to the client also via the secure channel. The result is then
displayed to the user.

The server is waiting for connections and spawns a thread for each
secure channel. The client is running in a loop and can pass more text
lines to be word counted to the server. The client is terminated by
writing a message "q" in a console.  The quit message is also passed
to the server that terminates the thread bound to the secure channel.

The demonstrator system running in qemu can be started using the
command:

      make run

This is starting a qemu-based Linux system with Keystone. It is
possible to login from a console using default credentials mentioned
in Keystone documentation (root/sifive). Note that the boot log also
mentions a port that is used by sshd to listen incoming
connections. After login Keystone kernel module should be loaded using
a command:

      modprobe keystone-driver

The server should be started by using a command:

      ./schannel-host ./schannel-eapp ./eyrie-rt ./loader

This is starting a server (in the top directory). The server is by
default bound to a port 3333. Use another shell in the host computer
to connect to the qemu using ssh comnection. The port number is listed
in the beginning of the boot log. Check the similar text as the
following in th ebeginning of the boot log:

      **** Running QEMU SSH on port 3000 ****

Use again the default credentials (root/sifive):

      ssh -l root -p <see boot log> localhost

After logging in connect to the server using a command:

      ./schannel-client localhost:3333

The enclave code calculates the number of words in a text line passed
to the enclave using secure channel. The value is also returned using
the same channel. The client first connects to the server and
establishes secure connection. After that multiple text lines can be
passed to the enclave and return values are received. The client can
terminate the connection by sending a one letter text line 'q'. The
server supports multiple concurret clients.

The server can be terminated using CTRL-C from the shell or with the
kill command. The qemu instance can be terminated using the halt
command.

## Known issues ##

The code is only meant to demonstrate the use of the Rust SDK.

The secure channel is vulnerable to man-in-the-middle
attacks. Certificates should be used to mitigate these threats.

There is no true randomness source.

There is a placeholder for remote attestation and there is also
attestation request and reply but the attestation evidence is not
verified.

Our Rust SDK is using deprecated 'to\_bits/from\_bits' functions that
should be replaced with other functions. This is generating compiler
warnings with newer Rust compiler versions.

Modified static-dh-ecdh must be used to get things compiled in no_std
environment for the enclave.

Remember to load the Keystone kernel module before trying this demo
using the insmod command.

Each qemu invocation will create a different ssh key for the sshd
server. The client connection will report that the remote host
identification has changed. You can remove the entry using the
command (assuming ssh port mapping for port 3000):

      ssh-keygen -f $HOME/.ssh/known_hosts -R "[localhost]:3000"

The code contains also quite a lot debug output.

# Acknowledgment

This work is partly supported by the European Union’s Horizon Europe
research and innovation programme in the scope of the the
[CONFIDENTIAL6G](https://confidential6g.eu/) project under Grant
Agreement 101096435.
