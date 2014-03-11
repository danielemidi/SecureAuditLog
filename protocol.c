#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "memutils.h"
#include "protocol.h"
#include "crypto_sym.h"
#include "crypto_digest.h"
#include "crypto_rsa.h"
#include "logentrytypes.h"

char currlogname[255];
int  currentryindex;

unsigned char *iv; // initialization vector for AES

char *a; // current value for a (will be updated for every entry)
char *y; // current value for y (will be updated for every entry)




void init_crypto() {
	ERR_load_crypto_strings();

	// load all cipher and digest algorithms, plus config initialization files
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
    
    /* Fix a 128-bit IV */
    iv = "a1b2c3d4e5f6g8h9";
}

void uninit_crypto() {
	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* Remove error strings */
	ERR_free_strings();
}





int getcurrentryindex() {
    return currentryindex;
}


// Compute the correct file name for a log and return a file descriptor for that file.
FILE * openlogfile(char *logname, const char *mode) {
    char logfilename[strlen(logname)+strlen("./.log")+1];
    strcpy(logfilename, "./");
	strcat(logfilename, logname);
	strcat(logfilename, ".log");
    
	FILE * fp = fopen(logfilename, mode);
	if (!fp)
	{
		fprintf(stderr, "Unable to open file %s.\r\n\r\n", logfilename);
		abort();
	}
	return fp;
}

// Read and return a binary buffer consisting of all the bytes from the current seek point until the next "\r\l" terminator.
// Return NULL if the end of the file is reached before any terminator (last bytes are considered invalid as per design format).
char * readnextlinefromlog(FILE *fp, int *linelen) {
	char buffer[ENC_DEC_BUF_SIZE];
	int currfi = 0;
    int freadresult = 1;
	int foundfirstterminator = 0;
	int foundsecondterminator = 0;
	char b[1];

	while (!foundsecondterminator) {
		if(fread(b, sizeof(char), 1, fp) == 0) return NULL;
		if(b[0] == '\r') foundfirstterminator = 1;
		else if(foundfirstterminator){
			if(b[0] == '\n') foundsecondterminator = 1;
			else foundfirstterminator = 0;
		}
		buffer[currfi] = b[0];
		currfi++;
	}
	
	int llen = currfi-2;
	char *line = (char *)malloc(llen);
	memcpy(line, buffer, llen);
	memcpy(linelen, &llen, sizeof(int));
	
	return line;
}

// Store a_0 for a specific log in a related file at T.
void storea_0forlog(char *logname, char *a_0) {
    char keyfilename[strlen(logname)+strlen("./.a_0.log")+1];
    strcpy(keyfilename, "./");
	strcat(keyfilename, logname);
	strcat(keyfilename, ".a_0.log");
    
	FILE * fp = fopen(keyfilename, "w+b");
	if (!fp) {
		fprintf(stderr, "Unable to open file %s.\r\n\r\n", keyfilename);
		abort();
	}
	
	fwrite(a_0, 32, 1, fp);
	
	fclose(fp);
}
// Read a_0 for a specific log from a related file at T.
char * reada_0forlog(char *logname) {
    char keyfilename[strlen(logname)+strlen("./.a_0.log")+1];
    strcpy(keyfilename, "./");
	strcat(keyfilename, logname);
	strcat(keyfilename, ".a_0.log");
    
	FILE * fp = fopen(keyfilename, "rb");
	if (!fp) {
		fprintf(stderr, "Unable to open file %s.\r\n\r\n", keyfilename);
		abort();
	}
	
	char *a_0 = malloc(32);
	fread(a_0, 32, 1, fp);
	
	fclose(fp);
	
	return a_0;
}






char * generate_k_i(int type, char *a_i) {
	int newksize = strlen("Encryption key") + sizeof(int)/*type*/ + 32/*a*/;
	char *newk = memcat(3, strlen("Encryption key"), "Encryption key", sizeof(int), &type, 32, a_i);
	char *k = hash(newk, newksize);
	free(newk);
	
	return k;
}

// Build a log entry (according to the protocol) from <type> and the len bytes in <data>.
int buildandstoreentry(int type, char *data, int len) {
    char *k = generate_k_i(type, a);
	
	char edata[ENC_DEC_BUF_SIZE];
	int edata_len = encrypt_sym(data, len, k, iv, edata);
	free(k);
	
	int newysize = 32/*y*/ + edata_len/*edata*/ + sizeof(int)/*type*/;
	char *newy = memcat(3, 32, y, edata_len, edata, sizeof(int), &type);
	free(y);
    y = hash(newy, newysize);
	free(newy);
	
	char *z = hmac(y, 32, a, 32);
	
	int entrysize = sizeof(int)/*type*/ + edata_len/*edata*/ + 32/*y*/ + 32/*z*/;
	char *entry = memcat(4, sizeof(int), &type, edata_len, edata, 32, y, 32, z);
	
	free(z);
	
	// store entry to log file
	FILE *fp = openlogfile(currlogname, "ab");
	currentryindex++;
	fwrite(entry, entrysize, 1, fp);
	fwrite("\r\n", 2, 1, fp);
	fclose(fp);
	free(entry);
	
	// increment A
    int newasize = strlen("Increment Hash")/*"Increment Hash"*/+32/*a*/;
	char *newa = memcat(2, strlen("Increment Hash"), "Increment Hash", 32, a);
	free(a);
	a = hash(newa, newasize); // increments previous a by overwriting it
	free(newa);
	
	return currentryindex;
}





unsigned int dtimeout;
char *temp_h_x_0;

void initlog_U(char *logname) {
    // create log file
    strcpy(currlogname, logname);
	currentryindex = -1;
	FILE *fp = openlogfile(currlogname, "w+");
	fclose(fp);
	
    // initialize y to 256 bits of zeros
	y = (char *)malloc(32);
	memset(y, 0, 32);

	char *idlog = "001";
	char *idu = "u";
	
	char *k_0 = gen_random_key(32);
	
	a = gen_random_key(32);
		// printf("a_0_U:\r\n");
		// BIO_dump_fp(stdout, a, 32);
		// printf("\r\n\r\n");
    
	unsigned int d = (unsigned)time(NULL);
	dtimeout = d + 3; // 3 seconds before timeout
	
    char *cu = NULL; // U's certificate file
    int cu_len = loadKeyFromFileAsBytes(PUBKEY_U_FILE, &cu);
    
    int x_0size = sizeof(char)/*0*/ + sizeof(unsigned int)/*d*/ + cu_len/*cu*/ + 32/*a*/;
	char *x_0 = memcat(4, sizeof(char), "0", sizeof(unsigned int), &d, cu_len, cu, 32, a);
	
    RSA *pk_t = loadRSAPublicKeyFromFile(PUBKEY_T_FILE);
    char *ek0 = RSA_encrypt(k_0, pk_t, 32);
    RSA *sk_u = loadRSAPrivateKeyFromFile(PRIVKEY_U_FILE);
    char *sig_x0 = RSA_sign_SHA256(hash(x_0, x_0size), sk_u);
    
    int x_0sig_x0size = x_0size/*x_0*/ + keysize(sk_u)/*sig_x0*/;
	char *x_0sig_x0 = memcat(2, x_0size, x_0, keysize(sk_u), sig_x0);
	free(sig_x0);
	free(sk_u);
        
	char ex0[ENC_DEC_BUF_SIZE];
	int ex0_len = encrypt_sym(x_0sig_x0, x_0sig_x0size, k_0, iv, ex0);
	free(k_0);
	free(x_0sig_x0);
    
    int m_0size = sizeof(char)/*0*/ + ID_LEN/*idu*/ + keysize(pk_t)/*ek0*/ + ex0_len/*ex0*/;
	char *m_0 = memcat(4, sizeof(char), "0", ID_LEN, idu, keysize(pk_t), ek0, ex0_len, ex0);
	free(pk_t);
	free(ek0);
	
	/// create first log entry
    int firstentrysize = sizeof(unsigned int)/*d*/ + sizeof(unsigned int)/*dtimeout*/ + IDLOG_LEN/*idlog*/ + m_0size/*m_0*/;
	char *firstentry = memcat(4, sizeof(unsigned int), &d, sizeof(unsigned int), &dtimeout, IDLOG_LEN, idlog, m_0size, m_0);
    
    buildandstoreentry(LOGFILEINITTYPE, firstentry, firstentrysize);
	free(firstentry);
	
	// store HASH(x_0) temporarily (for subsequent verifications)
    temp_h_x_0 = hash(x_0, x_0size);
	free(x_0);
	
    initlog_T(m_0, m_0size);
}

char *a_0_T;
void initlog_T(char *m, int mlen) {
	// unpack m -> x_0
	char *p = (char *)malloc(sizeof(char));
	char *idu = (char *)malloc(ID_LEN);
	char *ek0 = (char *)malloc(RSA_LEN);
	int ex0_len = mlen - sizeof(char) - ID_LEN - RSA_LEN;
	char *ex0 = (char *)malloc(ex0_len);
	memsplit(m, 4, sizeof(char), p, ID_LEN, idu, RSA_LEN, ek0, ex0_len, ex0);
    free(p);
    free(idu);
	free(m);
		
    RSA *sk_t = loadRSAPrivateKeyFromFile(PRIVKEY_T_FILE);
	char *k0 = RSA_decrypt(ek0, sk_t);
	free(ek0);
	
	char x_0sig_x0[ENC_DEC_BUF_SIZE];
	int x_0sig_x0size = decrypt_sym(ex0, ex0_len, k0, iv, x_0sig_x0);
	free(ex0);
	free(k0);
	
	int x_0size = x_0sig_x0size - RSA_LEN;
	char *x_0 = (char *)malloc(x_0size);
	char *sig_x0 = (char *)malloc(RSA_LEN);
    memsplit(x_0sig_x0, 2, x_0size, x_0, RSA_LEN, sig_x0);
	
	// unpack a_0 from x_0
	a_0_T = (char*)malloc(32);
	memcpy(a_0_T, x_0+(x_0size-32), 32);
	storea_0forlog(currlogname, a_0_T);
	
	char *hx_0 = hash(x_0, x_0size);
	
    // verify signature(hash(x_0))
    int cu_len = x_0size - (1+sizeof(int)+32);
    char *cu = malloc(cu_len);
    memcpy(cu, x_0+(1+sizeof(int)), cu_len);
	free(x_0);
    RSA *pk_u = loadRSAPublicKeyFromBuffer(cu, cu_len); //loadRSAPublicKeyFromFile(PUBKEY_U_FILE);
    if(!RSA_verify_SHA256(hx_0, pk_u, sig_x0)) {
        // Failed check
		printf("Error: cannot verify sign(x_0) from U.\r\n");
        return;
    // } else {
		// printf("Sign(x_0) from U VERIFIED.\r\n");
    }
	

    char *idlog = "001";
	char *idt = "t"; // idt = id of T
	
    int x_1size = sizeof(char)/*1*/ + IDLOG_LEN/*idlog*/ + 32/*hx_0*/;
	char *x_1 = memcat(3, sizeof(char), "1", IDLOG_LEN, idlog, 32, hx_0);
	free(hx_0);
	
	char *k_1 = gen_random_key(32);
	
    char *ek1 = RSA_encrypt(k_1, pk_u, 32);
    char *sig_x1 = RSA_encrypt(x_1, sk_t, x_1size);
	
	char *x_1sig_x1 = memcat(2, x_1size, x_1, keysize(pk_u), sig_x1);
	free(x_1);
	free(sig_x1);
	
	char ex1[ENC_DEC_BUF_SIZE];
	int ex1_len = encrypt_sym(x_1sig_x1, strlen(x_1sig_x1), k_1, iv, ex1);
	free(x_1sig_x1);
	free(k_1);
    
    int m_1size = sizeof(char)/*1*/ + ID_LEN/*idt*/ + keysize(pk_u)/*ek1*/ + ex1_len/*ex1*/;
	char *m_1 = memcat(4, sizeof(char), "1", ID_LEN, idt, keysize(pk_u), ek1, ex1_len, ex1);
	free(ek1);
	
	completeinitlog_U(m_1, m_1size);
}

void completeinitlog_U(char *m, int mlen) {
	// verify that timeout dtimeout is not expired
	unsigned int dnow = (unsigned)time(NULL);
	if(dnow > dtimeout) {
		printf("Error: timeout on log initialization.\r\n");
		char timestamp[100];
		snprintf(timestamp, 100, "%u", dnow);
		buildandstoreentry(ABNORMALCLOSETYPE, timestamp, strlen(timestamp));
		abort();
	}
	
    // verify that m is correct by checking that hx_0 from m is the hash of x_0
	char *ek1 = (char *)malloc(RSA_LEN);
	int ex1_len = mlen - sizeof(char) - ID_LEN - RSA_LEN;
	char *ex1 = (char *)malloc(ex1_len);
	memsplit(m+sizeof(char)+ID_LEN, 2, RSA_LEN, ek1, ex1_len, ex1);
    RSA *sk_u = loadRSAPrivateKeyFromFile(PRIVKEY_U_FILE);
	char *k1 = RSA_decrypt(ek1, sk_u);
	free(ek1);
	char x_0sig_x0[ENC_DEC_BUF_SIZE];
	int x_0sig_x0size = decrypt_sym(ex1, ex1_len, k1, iv, x_0sig_x0);
	free(ex1);
	free(k1);
	char *hx_0 = (char *)malloc(32);
    memcpy(hx_0, x_0sig_x0+1+IDLOG_LEN, 32);
    if(memcmp(hx_0, temp_h_x_0, 32) != 0) {
        // Failed check
		printf("Error: cannot verify hash(x_0) from T.\r\n");
        free(temp_h_x_0);
        free(m);
        return;
    }
    free(temp_h_x_0);
	
	buildandstoreentry(RESPONSEMESSAGETYPE, m, mlen);
	free(m);
}



void closelog_U() {
	char timestamp[100];
    snprintf(timestamp, 100, "%u", (unsigned)time(NULL));
	buildandstoreentry(NORMALCLOSETYPE, timestamp, strlen(timestamp));
	
    memset(a, 0, 32); // permanently delete a from the memory
}















char *ledata;
int ledata_len;

char * verifyentry_V(int entryindex) {
	if(entryindex > currentryindex) {
		printf("No such entry.\r\n");
		return NULL;
	}

	// initialize prevy = block of 32 zeros
	char *prevy = (char *)malloc(32);
	memset(prevy, 0, 32);
	
	FILE *fp = openlogfile(currlogname, "rb");
	int llen = 0; // length of l
	
	int lw = 0;
	ledata = (char *)malloc(1);
	char *ly = (char *)malloc(32);
	char *lz = (char *)malloc(32);
	
	int i;
	for(i=0; i<=entryindex; i++) {	
		char *l = readnextlinefromlog(fp, &llen);
		
		// unpack l -> {w, edata, y, z}
		ledata_len = llen - sizeof(int) - 32 - 32;
		free(ledata);
		free(ly);
		free(lz);
		ledata = (char *)malloc(ledata_len);
		ly = (char *)malloc(32);
		lz = (char *)malloc(32);
		memsplit(l, 4, sizeof(int), &lw, ledata_len, ledata, 32, ly, 32, lz);
		free(l);
		
		// verify that y = hash(y-1 || edata || w)
		int newysize = 32/*prevy*/ + ledata_len/*edata*/ + sizeof(int)/*type*/;
		char *newy = memcat(3, 32, prevy, ledata_len, ledata, sizeof(int), &lw);
		char *hnewy = hash(newy, newysize);
		free(newy);
		
		if(memcmp(hnewy, ly, 32) != 0) {
			// Failed verification
			fclose(fp);
			return NULL; // hnewy != ly -> error
		}
			
		free(hnewy);
		
		memcpy(prevy, ly, 32);
	}
	fclose(fp);
	
	// m_2 = "2" || idlog || entryindex || ly || lz || (entryindex || lw)
	char *idlog = "001";
	int m_2len = sizeof(char)/*"2"*/ + IDLOG_LEN/*idlog*/ + sizeof(int)/*entryindex*/ + 32/*ly*/ + 32/*lz*/ + sizeof(int)/*entryindex*/ + sizeof(int)/*lw*/;
	char *m_2 = memcat(7, sizeof(char), "2", IDLOG_LEN, idlog, sizeof(int), &entryindex, 32, ly, 32, lz, sizeof(int), &entryindex, sizeof(int), &lw);
	free(ly);
	free(lz);
		
	return verifyentry_T("V", m_2, m_2len);
}

char * verifyentry_T(char *vid, char *m, int mlen) {
	// unpack m -> "2" || idlog || entryindex || ly || lz || entryindex || lw
	char p[1];
	char idlog[IDLOG_LEN];
	int entryindex, lw;
	char ly[32];
	char lz[32];
	memsplit(m, 7, sizeof(char), p, IDLOG_LEN, idlog, sizeof(int), &entryindex, 32, ly, 32, lz, sizeof(int), &entryindex, sizeof(int), &lw);
    free(m);
	
	// calculate a_entryindex from a_0
	char *a_i = (char *)malloc(32);
	memcpy(a_i, a_0_T, 32);
	int i;
    int newasize = strlen("Increment Hash")/*"Increment Hash"*/+32/*a*/;
	for(i=1; i<=entryindex; i++) {
		char *newa = memcat(2, strlen("Increment Hash"), "Increment Hash", 32, a_i);
		free(a_i);
		a_i = hash(newa, newasize);
		free(newa);
	}
	
	// verify that lz==HMAC(ly, key: a_entryindex)
	char *newz = hmac(ly, 32, a_i, 32);
	if(memcmp(newz, lz, 32) != 0) {
        // Failed verification
        free(newz);
        free(a_i);
		return NULL; // lz != HMAC(ly, key: a_entryindex) -> error
	}
    free(newz);
	
	// verify that V is authorized to access entryindex
	if(!checkverifierpermissions_T(vid, lw)) {
        // Insufficient permissions
        free(a_i);
		return "Insufficient permissions.";
	}
	
    char *keyforentryindex = generate_k_i(lw, a_i);
    free(a_i);
	
	int m_3len = sizeof(char)/*"2"*/ + IDLOG_LEN/*idlog*/ + sizeof(int)/*entryindex*/ + 32/*ly*/ + 32/*lz*/ + sizeof(int)/*entryindex*/ + sizeof(int)/*lw*/;
	char *m_3 = memcat(3, sizeof(char), "3", sizeof(int), &entryindex, 32, keyforentryindex);
	
	return completeverifyentry_V(m_3, m_3len);
}

int checkverifierpermissions_T(char *vid, int entrytype) {
    // Here we can implement the permission mask check for all the verifiers.
    // For now, all the verifiers can access all the entry types.
    return 1;
}

char * completeverifyentry_V(char *m, int mlen) {
	// unpack m -> "3" || entryindex || keyforentryindex
	char p[1];
	int entryindex;
	char keyforentryindex[32];
	memsplit(m, 3, sizeof(char), p, sizeof(int), &entryindex, 32, keyforentryindex);
    free(m);
	
	// decrypt ledata (loaded in verifyentry_V()) with keyforentryindex
	char data[1024];
	int datasize = decrypt_sym(ledata, ledata_len, keyforentryindex, iv, data);
	free(ledata);
	
	data[datasize] = '\0';
	
    char *result = malloc(datasize+1);
    memcpy(result, data, datasize+1);
    
	return result;
}





void verifyallentries_T(char *logname, char *outfile) {
	// initialize prevy = block of 32 zeros
	char *prevy = (char *)malloc(32);
	memset(prevy, 0, 32);
    
    // initialize a_i = a_0 (already known to the server)
	char *a_i = reada_0forlog(logname);
    int newasize = strlen("Increment Hash")/*"Increment Hash"*/ + 32/*a*/;
	
	FILE *fp = openlogfile(logname, "rb");
    FILE *fpout = openlogfile(outfile, "w+");
	int llen = 0; // length of l
	
	int lw = 0;
	char *ledata;
	char *ly;
	char *lz;
	
	int i;
    for(i=0; 1==1; i++) {
        char *l = readnextlinefromlog(fp, &llen);
        if(l == NULL) break;
		
        // calculate a_i
		if(i>0) {
			char *newa = memcat(2, strlen("Increment Hash"), "Increment Hash", 32, a_i);
			free(a_i);
			a_i = hash(newa, newasize);
			free(newa);
		}
        
		// read line l and unpack l -> {w, edata, y, z}
		ledata_len = llen - sizeof(int) - 32 - 32;
		ledata = (char *)malloc(ledata_len);
		ly = (char *)malloc(32);
		lz = (char *)malloc(32);
		memsplit(l, 4, sizeof(int), &lw, ledata_len, ledata, 32, ly, 32, lz);
		free(l);
		
		// verify that y == hash(y-1 || edata || w)
		int newysize = 32/*prevy*/ + ledata_len/*edata*/ + sizeof(int)/*type*/;
		char *newy = memcat(3, 32, prevy, ledata_len, ledata, sizeof(int), &lw);
		char *hnewy = hash(newy, newysize);
		free(newy);
		if(memcmp(hnewy, ly, 32) != 0) {
			// Failed verification
            fprintf(fpout, "Failed verification.\r\n");
            free(hnewy);
            goto nextentry;
		}
		free(hnewy);
        
        // verify that z == HMAC(y, key: a_i)
        char *newz = hmac(ly, 32, a_i, 32);
        if(memcmp(newz, lz, 32) != 0) {
            // Failed verification
            fprintf(fpout, "Failed verification.\r\n");
            free(newz);
            goto nextentry;
        }
        free(newz);
        
        // calculate the decryption key for the current entry and decrypt it
        char *keyforentryindex = generate_k_i(lw, a_i);
        char data[ENC_DEC_BUF_SIZE];
        int datasize = decrypt_sym(ledata, ledata_len, keyforentryindex, iv, data);
        free(ledata);
        data[datasize] = '\0';
        fprintf(fpout, "%s\r\n", data);
		
nextentry:
		memcpy(prevy, ly, 32);
		free(ly);
		free(lz);
	}
    
    fclose(fpout);
	fclose(fp);
    free(a_i);
}