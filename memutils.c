#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "memutils.h"

/// memcat concatenates multiple byte buffers in a single buffer.
/// num: number of buffers to concatenate
/// variable args: sequence of couples <size, buffer pointer>
/// ex: char *output = memcat(3, 32, b1, 32, b2, sizeof(int), &d);
char * memcat(int num, ...) {
    va_list arguments;                     

	// calculate total buffer size
    int totsize = 0;
    va_start(arguments, num);
	int i;
    for (i = 0; i < num; i++) {
        totsize += va_arg(arguments, int);
		va_arg(arguments, char*);
    }
    va_end(arguments);
	
	// actually concatenate buffers
	char *buffer = (char *)malloc(totsize);
	char *memcpyi = buffer;
	va_start(arguments, num);
    for (i = 0; i < num; i++) {
        int size = va_arg(arguments, int);
		char *b = va_arg(arguments, char*);
		memcpy(memcpyi, b, size);
        memcpyi += size;
    }
    va_end(arguments);

	return buffer;
}


/// memsplit splits a single buffer into multiple buffers.
/// num: number of buffers to concatenate
/// variable args: sequence of couples <size, buffer pointer>
/// ex: char *output = memcat(3, 32, b1, 32, b2, sizeof(int), &d);
void memsplit(char * buffer, int num, ...) {
    va_list arguments;                     

	char *memcpyi = buffer;
	va_start(arguments, num);
	int i;
    for (i = 0; i < num; i++) {
        int size = va_arg(arguments, int);
		char *b = va_arg(arguments, char*);
		memcpy(b, memcpyi, size);
        memcpyi += size;
    }
    va_end(arguments);
}