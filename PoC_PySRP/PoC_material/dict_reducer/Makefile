SRC = cpuid.c sha.c sha1_ni-x86.c trace_verif.c main.c 
SHA_NI_FLAGS = -msse4.1 -msha
OPENSSL_FLAG = -lcrypto
OPENMP_FLAG = -fopenmp
FLAGS = -O3 $(OPENMP_FLAG) $(SHA_NI_FLAGS)

all:
	gcc $(FLAGS) $(SRC) -o dict_reducer $(OPENSSL_FLAG)
