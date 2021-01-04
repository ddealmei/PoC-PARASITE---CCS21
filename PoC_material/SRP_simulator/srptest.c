#include <stdio.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/srp.h>

int main(int argc, char const *argv[])
{
	
    if (argc != 4) {
        printf("Usage: %s ID PASSWORD SALT\n", argv[0]);
        return 0;
    }
    const char *id = argv[1];
    const char *pwd = argv[2];
    BIGNUM *s = NULL;
    BN_hex2bn(&s, argv[3]);
    
    /* Compute x from the inputs */
    BIGNUM *x = SRP_Calc_x(s, id, pwd);
    
    /* Get group paramters */
    const SRP_gN *GN;
    GN = SRP_get_default_gN("6144");
    
    /* Generate random values for B, a and u since we do not really run the protocol */
    BIGNUM *B = BN_new(), *a = BN_new(), *u = BN_new();
    BN_rand(B, 6143, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_rand(a, 6143, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_rand(u, 160, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    /* 
    * SRP_Calc_client performs quite a few operations, including the modular 
    * exponentiation we target. 
    */
    SRP_Calc_client_key(GN->N, B, GN->g, x, a, u);
    
    BN_free(s);
    BN_free(x);
    BN_free(B);
    BN_free(a);
    BN_free(u);

	return 0;
}

