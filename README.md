# encrypt-decrypt
encrpty request body with RSA public key and decrypt the same encrypted message with respective RSA private key


private key generation command:openssl genrsa -out privatekey.pem 2048

public key generation command: openssl rsa -in privatekey.pem -out publickey.pem -pubout -outform PEM

https://www.webdevsplanet.com/post/how-to-generate-rsa-private-and-public-keys
