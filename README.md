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

If zccserv is able to start successfully, you will see a message like the following:

```
Listening on port 4104
```

Note that Ctrl-C will terminate zccserv.

Download zccgui.py and zcclient.py to the same directory on your Windows, Linux or Mac OS workstation.  If necessary, install Python 3.11 or later (including _tkinter_, which is a standard Python package, but may need to be explicitly installed on Linux).  Use pip to install the _pillow_ Python package (optional).

## Running zccgui

_zccgui_ will accept hostname/IP and port number as command-line arguments, or you can type these values into the input fields on the top banner of the GUI.  Invoke _zccgui_ as follows:

```
python3 zccgui.py [host port]
```



