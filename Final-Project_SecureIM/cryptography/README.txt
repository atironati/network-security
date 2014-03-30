Alex Tironati

Network Security Problem Set 2
-----------------------------------------------

In my implementation of Problem Set 2 I have created two executable
Python files, one being the main fcrypt program and the other a utility
for generating RSA private/public key pairs. Here are the usages:

fcrypt.py [-e destination_public_key_filename sender_private_key_filename input_plaintext_file output_cyphertext_file]
          [-d destination_private_key_filename sender_public_key_filename input_cyphertext_file output_plaintext_file]

key_generator.py public_key_filename private_key_filename 

Here are the typical commands I use to test fcrypt with the keys I have
generated. This demonstrates the intended functionality between a sender
(Alice) and a recipient (Bob):

./fcrypt.py -e bob_pub.txt alice_priv.txt msg.txt encrypted.txt
./fcrypt.py -d bob_priv.txt alice_pub.txt encrypted.txt decrypted.txt

To test that my signing scheme works, you may use these commands:

./fcrypt.py -e bob_pub.txt oscar_priv.txt msg.txt encrypted.txt
./fcrypt.py -d bob_priv.txt alice_pub.txt encrypted.txt decrypted.txt
          

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


---------- Algorithms and Key Sizes -----------
-----------------------------------------------

** Encryption

In order to fulfill the requirement of using both symmetric and
asymmetric encryption schemes, and to make the most efficient
implementation, I combined the use of RSA encryption and AES
encryption. My encryption scheme uses a 4-part process to
accomplish this:

         1. Generate a random session key and initialization vector (IV)

This random session key ensures that the data I encrypt will not be
encrypted the same way every time, making it much harder for an attacker
to break or understand. I use PyCrypto's random module here to do the 
generation (it is much stronger than the standard Python random module).
The session key is 128 bits long, a typical size for use with these
algorithms, and the IV is 64 bits long, which is necessary to match the 
block size for my use of AES. 

         2. Encrypt session key using PKCS1 OAEP public key crypto

Here I use the public key of the recipient to encrypt the session key 
combined with the IV so that I may retrieve both when decrypting. I
use asymmetric encryption with the PKCS1 OAEP standard, which is
considered very secure due to its randomized padding scheme. I am 
using this algorithm to encrypt the session key and not the message 
because asymmetric encryption is slow and subject to limitations based 
on the key size used. Since I am using a key size of 2048 bits, I can 
safely encode the 192-bit combined session key and IV with ease. 

         3. Encrypt plaintext using AES in CBC mode with a random IV

Now that I have a securely-encrypted session key, I can use that as an
input to an AES symmetric encryption algorithm to quickly encrypt the
message I want to send. I use Cipher Block Chaining as an AES mode
because it is considered much more secure than the default ECB. CBC
encrypts each block with the result of the previously-encrypted block,
which makes it much harder to decrypt because if you are missing any
blocks in the sequence you will lose the structure of the encryption.
The use of an IV also makes it much more secure because it introduces 
a random element for each encryption. Note that the plaintext must be
padded so that it may fit with the block size of the AES algorithm.

         4. Sign the encrypted file using the sender's private key and PKCS1_v1_5

The last step is to sign the file so that the recipient can ensure that
the message is authentic. Here I use the PKCS1_v1_5 standard because it
was included with PyCrypto and is a reliable signature scheme based on
the PKCS1 standard. In this step I create a 256 bit random string
(separate from the session key or IV) to use as a message. I sign this
message and then include both the digest and the message in the
encrypted file so that the recipient may verify it.


** Decryption

My decryption scheme essentially follows the above steps in reverse. It 
first verifies the signature by computing a digest of the given signature
message using the expected sender's public key and comparing that
against the provided digest to ensure they match. If at any time it
detects an incorrect key or signature it will immediately exit. Once the
sender has been verified it continues to decrypt by first obtaining the
session key and IV through PKCS1 OEAP and then using that to decrypt the
message using AES. 


** RSA Key sizes

I use a 2048 bit long RSA key in my generator, as this is the 
currently-recommended length:

         http://www.emc.com/emc-plus/rsa-labs/historical/has-the-rsa-algorithm-been-compromised.htm

An exponent of 65537 (represented in hex as 0x10001) is used because this 
particular value is prime and makes the modular exponentiation operation 
faster, having only two bits of value.


-------- Security of Algorithms Used ----------
-----------------------------------------------

** AES is known to be secure enough for government use:

"The design and strength of all key lengths of the AES algorithm (i.e., 128, 192
and 256) are sufficient to protect classified information up to the
SECRET level. TOP SECRET information will require use of either the 192
or 256 key lengths. The implementation of AES in products intended to
protect national security systems and/or information must be reviewed
and certified by NSA prior to their acquisition and use."

http://csrc.nist.gov/groups/ST/toolkit/documents/aes/CNSS15FS.pdf


** And PKCS is based on RSA, which is considered secure when implemented
with proper randomized padding schemes, which PCKS enforces and makes
extensive use of through OAEP. A thorough explanation can be found here:

http://security.stackexchange.com/questions/32050/what-specific-padding-weakness-does-oaep-address-in-rsa


---------------- Conclusion -------------------
-----------------------------------------------

In combining public-key encryption through my use of RSA and the
PKCS1-OEAP standard with AES encryption using CBC mode I have been 
able to combine the security benefits of public-key cryptography with 
the speed benefits of one-way hashing functions, resulting in a secure,
reliable, and easy to use encryption/decryption scheme.

