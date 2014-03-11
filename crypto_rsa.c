#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "crypto_err.h"
#include "crypto_rsa.h"

RSA * loadRSAPublicKeyFromFile(char *filename) {
    RSA *rsa_key = NULL;
    FILE *keyfile = fopen(filename,"rb");
	if (!keyfile)
	{
		fprintf(stderr, "Unable to open RSA Public Key file %s.\r\n\r\n", filename);
		abort();
	}
	//PEM_read_RSAPublicKey(keyfile, &rsa_key, NULL, NULL); // For PKCS#1 format
    PEM_read_RSA_PUBKEY(keyfile, &rsa_key, NULL, NULL);     // For PEM (x509) format
    if (rsa_key == NULL)
    {
        fprintf(stderr, "Error loading RSA Public Key from file:\n");
        handleErrors();
    }
	fclose(keyfile);
	return rsa_key;
}
RSA * loadRSAPrivateKeyFromFile(char *filename) {
    RSA *rsa_key = NULL;
    FILE *keyfile = fopen(filename,"rb");
	if (!keyfile)
	{
		fprintf(stderr, "Unable to open RSA Public Key file %s.\r\n\r\n", filename);
		abort();
	}
	PEM_read_RSAPrivateKey(keyfile, &rsa_key, NULL, NULL);
    if (rsa_key == NULL)
    {
        fprintf(stderr, "Error loading RSA Private Key from file:\n");
        handleErrors();
    }
	fclose(keyfile);
	return rsa_key;
}

int loadKeyFromFileAsBytes(char *filename, char **buffer) {
	FILE *keyfile;
	unsigned long len;

	keyfile = fopen(filename, "rb");
	if (!keyfile) {
		fprintf(stderr, "Unable to open RSA Key file %s", filename);
		return;
	}
	
	fseek(keyfile, 0, SEEK_END);
	len = ftell(keyfile);
	fseek(keyfile, 0, SEEK_SET);

	*buffer = (char *)malloc(len + 1);
	if (!*buffer) 	{
		fprintf(stderr, "Memory error!");
        fclose(keyfile);
		return;
	}
	fread(*buffer, len, 1, keyfile);
	fclose(keyfile);

	return len;
}

RSA * loadRSAPublicKeyFromBuffer(char *pub_key_buf, int buf_len) {
    BIO *pk_bio = BIO_new_mem_buf((void*)pub_key_buf, buf_len);
    RSA *rsa_key = NULL;
    PEM_read_bio_RSA_PUBKEY(pk_bio, &rsa_key, NULL, NULL);
    if (rsa_key == NULL) handleErrors();
    return rsa_key;
}

int keysize(RSA *key) {
	return RSA_size(key);
}

char * RSA_encrypt(char *msg, RSA *key, int len) {
	int encrypt_len;
	char *encrypt = malloc(RSA_size(key));
	
	if((encrypt_len = RSA_public_encrypt(len, (unsigned char*)msg, (unsigned char*)encrypt, key, RSA_PKCS1_OAEP_PADDING)) == -1) {
		fprintf(stderr, "Error encrypting message with RSA:\n");
        handleErrors();
	}
	
	return encrypt;
}

char * RSA_decrypt(char *msg, RSA *key) {
	char *decrypt = malloc(RSA_size(key));
	if(RSA_private_decrypt(RSA_size(key), (unsigned char*)msg, (unsigned char*)decrypt, key, RSA_PKCS1_OAEP_PADDING) == -1) {
		fprintf(stderr, "Error decrypting message with RSA:\n");
        handleErrors();
	}
	
	return decrypt;
}

char * RSA_sign_SHA256(char *msg, RSA *key) {
	int sig_len;
	char *sig = malloc(RSA_size(key));
	
	if(RSA_sign(EVP_MD_type(EVP_sha256()), (unsigned char*)msg, 32/*SHA-256*/, (unsigned char*)sig, &sig_len, key) == 0) {
		fprintf(stderr, "Error signing message with RSA:\n");
        handleErrors();
	}
	
	return sig;
}


/// The verification returns 1 in case of success, 0 otherwise.
int RSA_verify_SHA256(char *msg, RSA *key, char *sig) {
	return RSA_verify(EVP_MD_type(EVP_sha256()), (unsigned char*)msg, 32/*SHA-256*/, sig, RSA_size(key), key);
}