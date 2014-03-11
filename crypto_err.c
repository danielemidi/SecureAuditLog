#include <openssl/err.h>
#include "crypto_err.h"

void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
}