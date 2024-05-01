# Secure-Communication-using-Symmetric-and-Asymmetric-Hybrid-Encryption

Client creates a key pair using RSA and sends the public key to the server when connecting.
The server creates a random key and salt, encrypts them with the client's public key and send it back to client.
Client uses it's private key to decrypt the encrypted key and salt. Then client and server uses the same key, salt and cipher generated with the key and salt to further exchange messages.

## The Project uses:
1) Tkinter for GUI
2) Socket for communication
3) RSA for Asymmetric encryption
4) AES for Symmetric encryption

## Requirements:
```
pip install rsa
pip install pycryptodome
```
## How to Run:
```
python server/server.py
python client/client.py
```