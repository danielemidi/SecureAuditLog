#ifndef CRYPTO_SYM_H
#define CRYPTO_SYM_H

unsigned char * gen_random_key(int keyleninbytes);

int encrypt_sym(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt_sym(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

#endif