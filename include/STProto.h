#include <stdlib.h>
#include <stdint.h>

#define PLAIN 0
#define ZSTD 1
#define GZIP 2
#define LZMA2 3

#define METHOD_SEND 2
#define METHOD_OK 3
#define METHOD_REQUEST_RESEND 4

#define ENCRYPRION_AES128GCM 1
#define ENCRYPRION_AES256GCM 2
#define ENCRYPRION_CHACHA20 3
#define ENCRYPRION_AES128CCM 4
#define ENCRYPRION_AES256CCM 5

typedef void * STServer;
typedef void * STClient;

STServer STProto_bind(char *, uint16_t);
void STProto_listen(STServer);
STClient STProto_accept(STServer);
STClient STProto_connect(char *, uint16_t, uint8_t);
char * STProto_read(STClient, size_t *);
void STProto_write(STClient, char *, size_t);
