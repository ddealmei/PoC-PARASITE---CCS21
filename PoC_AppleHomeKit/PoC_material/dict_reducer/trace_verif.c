#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "main.h"

#define ABS_DIFF(x, y) (x) > (y) ? (x) - (y) : (y) - (x);

void bytes_to_bits(uint8_t *x_bytes, uint8_t *x_bits) {
    for(int i = 0; i < SHA_BYTE_LEN; i++) {
        x_bits[8*i] = (x_bytes[i] >> 7) & 0x01;
        x_bits[8*i + 1] = (x_bytes[i] >> 6) & 0x01;
        x_bits[8*i + 2] = (x_bytes[i] >> 5) & 0x01;
        x_bits[8*i + 3] = (x_bytes[i] >> 4) & 0x01;
        x_bits[8*i + 4] = (x_bytes[i] >> 3) & 0x01;
        x_bits[8*i + 5] = (x_bytes[i] >> 2) & 0x01;
        x_bits[8*i + 6] = (x_bytes[i] >> 1) & 0x01;
        x_bits[8*i + 7] = x_bytes[i] & 0x01;
    }
}

int compute_x(const Trace *trace, const char *pwd, const SRP_CTX *ctx, uint8_t *x) {
    uint8_t buf1[128] = {0};
    uint8_t buf2[SHA_BYTE_LEN + SALT_LEN];
    size_t buf1_len = strlen(pwd) + trace->id_len + 1;
    if (buf1_len + 1 > 120) {
        return -1;
    }

    // tmp = SHA1(id || ':' || pwd)
    memcpy(buf1, trace->id, trace->id_len);
    buf1[trace->id_len] = ':';
    memcpy(buf1 + trace->id_len + 1, pwd, strlen(pwd));
    ctx->sha(buf1, buf1_len, buf2 + SALT_LEN);

    // x = SHA1(salt || tmp)
    memcpy(buf2, trace->salt, SALT_LEN);
    ctx->sha_fixed_size(buf2, x);

    return 0;
}

static void hash_init(EVP_MD_CTX** ctx, const EVP_MD* type) {
    *ctx = EVP_MD_CTX_create();
    int ret = EVP_DigestInit_ex(*ctx, type, NULL);
}

static void hash_update(EVP_MD_CTX** ctx, const uint8_t* data, size_t size) {
    int ret = EVP_DigestUpdate(*ctx, data, size);
}

static void hash_final(EVP_MD_CTX** ctx, uint8_t* md) {
    int ret = EVP_DigestFinal_ex(*ctx, md, NULL);
    EVP_MD_CTX_destroy(*ctx);
    *ctx = NULL;
}

int compute_x_2(const Trace *trace, const char *pwd, const SRP_CTX *ctx, uint8_t *x) {
    EVP_MD_CTX* ctx_sha;
   
    hash_init(&ctx_sha, EVP_sha512());
    hash_update(&ctx_sha, trace->id, trace->id_len);
    hash_update(&ctx_sha, (const uint8_t*) ":", 1);
    hash_update(&ctx_sha, pwd, strlen(pwd));
    hash_final(&ctx_sha, x);

    hash_init(&ctx_sha, EVP_sha512());
    hash_update(&ctx_sha, trace->salt, SALT_LEN);
    hash_update(&ctx_sha, x, SHA_BYTE_LEN);
    hash_final(&ctx_sha, x);

    return 0;
}

void get_expected_pattern(uint8_t x[SHA_BYTE_LEN], Trace *trace) {
    int r_is_one = 1;
    uint64_t w, next_w;
    int b, bits;

    uint8_t x_bin[SHA_BIT_LEN] = {0};
    bytes_to_bits(x, x_bin);

    memset(trace->chunk_length, 0, SHA_BIT_LEN);

    bits = SHA_BIT_LEN;
    int i = 0;
    while (x_bin[i++] == 0) 
        bits--;
    w = SRP_BASE;
    for (b = SHA_BIT_LEN - bits+1; b < SHA_BIT_LEN; b++)
    {
        next_w = w * w;
        if ((next_w / w) != w)
        {
            next_w = 1;
            trace->nb_chunks++;
            if (r_is_one){
                trace->nb_chunks = 0;
                r_is_one = 0;
            }
        }
        w = next_w;

        if (!r_is_one)
            trace->chunk_length[trace->nb_chunks]++;
        
        if (x_bin[b] == 1){
            next_w = w * SRP_BASE;
            if ((next_w / SRP_BASE) != w)
            {
                next_w = SRP_BASE;
                trace->nb_chunks++;
                if (r_is_one)
                {
                    trace->nb_chunks = 0;
                    r_is_one = 0;
                }
            }
            w = next_w;
        }
    }
    trace->nb_chunks++;
}

// Checks if the reference trace matches the candidate password, 
// the lower the score, the higher the match
int get_difference_score(const Trace *ref, const Trace *x) {
    int i = x->nb_chunks;
    int j = ref->nb_chunks;
    // score intialized with the difference of number of chunks in the trace
    int score = ABS_DIFF(i, j);

    // then we increase the score for each chunk if they do not match
    while (i-- != 0 && j-- != 0) 
        score += ABS_DIFF(x->chunk_length[i], ref->chunk_length[j]);

    return score;
}

int check_trace(const Trace *trace, const char *pwd, const SRP_CTX *ctx) {
    uint8_t x[SHA_BYTE_LEN];
    Trace candidat;

    if (compute_x_2(trace, pwd, ctx, x) != 0) {
        fprintf(stderr, "An error occurred when computing x: may be the input was too long (\"%s:%s\")\n", pwd, trace->id);
    } 

    // Reproduce the pattern we would have got by computing g^x mod n 
    // with OpenSSL
    get_expected_pattern(x, &candidat);

    return get_difference_score(trace, &candidat);
}