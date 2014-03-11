#ifndef CRYPTO_DIGEST_H
#define CRYPTO_DIGEST_H

unsigned char * hash(unsigned char *data, int datalen);
unsigned char * hmac(char *data, int datalen, char *key, int keylen);

#endif