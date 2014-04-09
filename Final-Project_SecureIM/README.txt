CS 4740
Secure Instant Messaging Application
Alex Tironati
Mark Haynes

==Authorized Users:
Username		Password
alex			  alex
mark	      mark	
bob		      bob	

==Installation Instructions:
The provided public and private keys should be stored in the "keys" directory, which should
be in the same directory as the server_db.db, client.py, server.py, and common.py files.

The PyCrypto library needs to be installed, see instructions below.

The server should be run first, it can take no arguments, or a port can be specified.
The client takes the server's host and port as arguments.
The client will prompt the user for username and password once it is run.

Install PyCrypto:

------------- Installing PyCrypto -------------
-----------------------------------------------

Fcrypt makes extensive use of the Python library PyCrypto. I was able to
install this library on my mac by simply executing the command 

         'sudo easy_install PyCrypto'

If you are using windows you can try installing one of the prebuilt 
binaries here:

         http://www.voidspace.org.uk/python/modules.shtml#pycrypto

If those don't work you can try using pip (a Python package manager) 
to install the package with

         'sudo pip install pycrypto'

Finally you can download the library directly from the main site here:

         https://www.dlitz.net/software/pycrypto/

