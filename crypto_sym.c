#include <openssl/conf.h>
#include <openssl/evp.h>
#include <string.h>
#include "crypto_err.h"
#include "crypto_sym.h"

unsigned char * gen_random_key(int keyleninbytes) {
	unsigned char *buffer = (unsigned char *)malloc(keyleninbytes);
	if(1 != RAND_bytes(buffer, keyleninbytes)) handleErrors();
	return buffer;
}

int encrypt_sym(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt_sym(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}