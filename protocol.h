#ifndef PROTOCOL_H
#define PROTOCOL_H

#define IDLOG_LEN	3
#define ID_LEN		1
#define RSA_LEN		256
#define ENC_DEC_BUF_SIZE 3072

void init_crypto();
void uninit_crypto();

int buildandstoreentry(int type, char *data, int len);

int getcurrentryindex();


void initlog_U(char *logname);
void initlog_T(char *m, int mlen);
void completeinitlog_U(char *m, int mlen);

void closelog_U();

char * verifyentry_V(int entryindex);
char * verifyentry_T(char *vid, char *m, int mlen);
int checkverifierpermissions_T(char *vid, int entrytype);
char * completeverifyentry_V(char *m, int mlen);

void verifyallentries_T(char *logname, char *outfile);

#endif