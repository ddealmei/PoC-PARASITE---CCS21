#ifndef DICT_REDUCER_MAIN_H
#define DICT_REDUCER_MAIN_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_PWD_SIZE 16
#define SHA_BIT_LEN 512
#define SHA_BYTE_LEN 64
#define MAX_ID_LEN 32
#define SALT_LEN 16
#define SRP_BASE 5

#define DIFF_THRESHOLD 70

typedef struct {
    uint8_t salt[SALT_LEN];
    char id[MAX_ID_LEN];
    uint8_t id_len;
    uint8_t chunk_length[SHA_BIT_LEN];
    uint8_t nb_chunks;
} Trace;


typedef struct {
    void (*sha)(uint8_t *, size_t, uint8_t*);
    void (*sha_fixed_size)(uint8_t *, uint8_t *);
} SRP_CTX;

void SHA1_ni(uint8_t *in, size_t in_len, uint8_t* out);
void SHA1_ni_fixed(uint8_t *in, uint8_t* out);
void SHA1_soft(uint8_t *in, size_t in_len, uint8_t* out);
void SHA1_soft_fixed(uint8_t *in, uint8_t* out);
int supports_sha_ni(void);
int check_trace(const Trace *trace, const char *pwd, const SRP_CTX *ctx);

void SHA512_soft(uint8_t *in, size_t in_len, uint8_t* out);
void SHA512_soft_fixed(uint8_t *in, uint8_t* out);

#endif
