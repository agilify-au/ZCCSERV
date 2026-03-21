# ZCCSERV
Zero-Client Crypto Front-end and Server package (no charge, for development purposes)

**zccgui.py** is a Python GUI which makes calling IBM CCA cryptographic verbs very easy.

**zcclient.py** is a Python command-line utility for calling CCA verbs.  zccgui.py constructs the zcclient command needed to replicate what you are doing in zccgui.

**zccserv** is the z/OS UNIX _backend_ utility that executes verbs against the local ICSF for the LPAR where zccserv is running.  zccgui.py and zcclient.py communicate over a TCP socket (optionally using TLS 1.2 or 1.3).


