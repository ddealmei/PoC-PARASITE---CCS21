#include <openssl/sha.h> 
#include <stdint.h>

void SHA1_soft(uint8_t *in, size_t in_len, uint8_t *out) {
    SHA1(in, in_len, out);
}

/* We assume the input is 28 bytes long 
   (salt || sha(id || pwd)). It allows some optimizations
   on the SHA_NI version, so this function is needed for 
   compatibility */
void SHA1_soft_fixed(uint8_t *in, uint8_t *out) {
    SHA1_soft(in, 28, out);
}