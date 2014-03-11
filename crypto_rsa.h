#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <openssl/rsa.h>

#define PRIVKEY_T_FILE   "./keyT.pem"
#define PUBKEY_T_FILE    "./pub-keyT.pem"
#define PRIVKEY_U_FILE   "./keyU.pem"
#define PUBKEY_U_FILE    "./pub-keyU.pem"

RSA * loadRSAPublicKeyFromFile(char *filename);
RSA * loadRSAPrivateKeyFromFile(char *filename);

int loadKeyFromFileAsBytes(char *filename, char **buffer);
RSA * loadRSAPublicKeyFromBuffer(char *pub_key_buf, int buf_len);

int keysize(RSA *key);

char * RSA_encrypt(char *msg, RSA *key, int len);
char * RSA_decrypt(char *msg, RSA *key);

char * RSA_sign_SHA256(char *msg, RSA *key);
int RSA_verify_SHA256(char *msg, RSA *key, char *sig);

#endif