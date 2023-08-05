#include <stdlib.h>
#include <stdint.h>

#define NULL_DATA 0
#define BINARY 1
#define ASCII 2
#define ANSI 3
#define UTF_8 4
#define UTF_16LE 5
#define UTF_16BE 6
#define GBK 7
#define GB_2312 8
#define GB_18030 9
#define SHIFTJS 10
#define ZSTD 11
#define GZIP 12
#define LZMA2 13

#define METHOD_SEND_DATA 2
#define METHOD_OK 3
#define METHOD_REQUEST_RESEND 4

typedef void * STServer;
typedef void * STClient;

STServer STProto_bind(char *, uint16_t);
void STProto_listen(STServer);
STClient STProto_accept(STServer);
STClient STProto_connect(char *, uint16_t);
char * STProto_read(STClient, size_t *);
void STProto_write(STClient, char *, size_t);
