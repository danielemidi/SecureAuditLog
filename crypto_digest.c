#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "crypto_err.h"
#include "crypto_digest.h"

unsigned char * hash(unsigned char *data, int datalen){
	EVP_MD_CTX *mdctx;
	
	if((mdctx = EVP_MD_CTX_create()) == NULL) handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, data, datalen)) handleErrors();

	unsigned char *digest;
	if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) handleErrors();

	unsigned int *digest_len;
	digest_len = (int *)malloc(sizeof(unsigned int));
	if(1 != EVP_DigestFinal_ex(mdctx, digest, digest_len)) handleErrors();
		
	EVP_MD_CTX_destroy(mdctx);
	
	return digest;
}

unsigned char * hmac(char *data, int datalen, char *key, int keylen) {    
    unsigned char* digest;
    
    digest = HMAC(EVP_sha256(), key, keylen, (unsigned char*)data, datalen, NULL, NULL);

	unsigned char *md = (unsigned char *)malloc(32);
	memcpy(md, digest, 32);
	
    return md;
}