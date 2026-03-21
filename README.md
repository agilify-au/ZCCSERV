# ZCCSERV
Zero-Client Crypto Front-end and Server package (no charge, for development purposes)

**zccgui.py** is a Python GUI which makes calling IBM CCA cryptographic verbs very easy.

**zcclient.py** is a Python command-line utility for calling CCA verbs.  zccgui.py constructs the zcclient command needed to replicate what you are doing in zccgui.

**zccserv** is the z/OS UNIX _backend_ utility that executes CCA verbs against the local ICSF instance in the LPAR where zccserv is running.  zccgui and zcclient communicate over a TCP socket (optionally using TLS 1.2 or 1.3).

## Installation
Copy zccserv, in BINARY mode, to a zFS directory on z/OS.

From z/OS UNIX (USS) shell, mark zccserv as executable:

```
chmod +x zccserv
```

Start zccserv, specifying a suitable port number to listen on:

```
./zccserv 4104
```

Note that Ctrl-C will terminate zccserv.
