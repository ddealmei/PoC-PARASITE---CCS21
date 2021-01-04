#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <omp.h>

#include "main.h"

void usage(const char *name)
{
    fprintf(stderr, "USAGE: %s dict TRACE [TRACE ...]\nwhere dict is the dictionary file and TRACE=salt,id,x with", name);
    fprintf(stderr, "\n\t* salt an hexadecimal string");
    fprintf(stderr, "\n\t* id a user id (string)");
    fprintf(stderr, "\n\t* x a decomposition of the exponentiation  as a list of number of operations between Montgomery reduction.\n");
}

void parseTrace(char *str, Trace *trace) {
    uint64_t tmp;

    // First field is the salt
    tmp = strtol(str, &str, 16);
    for (int i = SALT_LEN-1; i >= 0; --i)
    {
        trace->salt[i] = tmp & 0XFF;
        tmp = tmp >> 8;
    }
    str++;
    
    // Second field is the id
    int i = 0;
    do
    {
        trace->id[i++] = *str;
        str++;
    } while (*str != ',');
    trace->id_len = i;

    // Copy the pattern
    trace->nb_chunks = 0;
    while (*str != '\0')
    {
        str++;
        trace->chunk_length[trace->nb_chunks] = strtol(str, &str, 10);
        trace->nb_chunks++;
    }
}

int main(int argc, char const *argv[])
{
    FILE *fp = NULL;
    char *Talloc = NULL;
    char **dict = NULL;
    Trace *traces = NULL;
    SRP_CTX *ctx = NULL;

    ctx = malloc(sizeof (SRP_CTX));
    if (ctx == NULL)
    {
        fprintf(stderr, "[-] Error while allocating ctx\n");
        goto end;
    }

    // We are having an issue with hardware instruction, need to look at the implementation
    // if (supports_sha_ni()) {
    //     fprintf(stderr, "[+] Supporting SHA_NI\n");
    //     ctx->sha = &SHA1_ni;
    //     ctx->sha_fixed_size = &SHA1_ni_fixed;
    // }
    // else {
    //     fprintf(stderr, "[-] No SHA_NI, fallback to OpenSSL\n");
        ctx->sha = &SHA1_soft;
        ctx->sha_fixed_size = &SHA1_soft_fixed;
    // }

    if (argc < 3) {
        usage(argv[0]);
        goto end;
    }

    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "[-] Error while opening dictionary (%s)\n", argv[1]);
        goto end;
    }

    int nTraces = argc - 2;
    traces = malloc(nTraces * sizeof(Trace));
    if (!traces) {
        fprintf(stderr, "[-] Error while allocating traces\n");
        goto end;
    }
    for (int i = 0; i < nTraces; ++i)
        parseTrace((char *) argv[i+2], &traces[i]);
    
    fprintf(stderr, "[+] Reading dictionary...\n");
    uint64_t nbLines = 0;
    while(!feof(fp))
        if(fgetc(fp) == '\n')
            nbLines++;
    rewind(fp);
    fprintf(stderr, "\t[+] %lu passwords in the dictionary\n", nbLines);

    // We read the file once and for all, storing all password in RAM
    Talloc = malloc(nbLines*MAX_PWD_SIZE);
    dict = malloc(nbLines*sizeof(char*));
    for(uint64_t i = 0 ; i < nbLines ; i++)
        dict[i] = &Talloc[MAX_PWD_SIZE*i];

    for(uint64_t i = 0; i < nbLines; i++) {
        if (fgets(dict[i], MAX_PWD_SIZE, fp) != NULL){
            // If there is no new line, it means the entry exceed the max size,
            // we just ignore the rest of the line
            if (dict[i][strlen(dict[i]) - 1] != '\n') {
                while (fgetc(fp) != '\n');
                dict[i][MAX_PWD_SIZE-1] = 0;
            }
            else
                dict[i][strlen(dict[i]) - 1] = 0;
        }
    }
    fprintf(stderr, "\t[+] All password loaded in memory\n");
    fclose(fp); 
    fp = NULL;

    int n_threads = omp_get_max_threads();
    fprintf(stderr, "[+] Starting test using %d threads\n", n_threads);
    omp_set_num_threads(n_threads);

    float min_score = (float)SHA_BIT_LEN;
    char *most_probable_pwd = NULL;
#pragma omp parallel for shared(dict,traces,ctx) schedule(static)
    for(uint64_t i = 0; i < nbLines; i++) {
        bool ok = true;
        float diff_score = 0;

        for (int j = 0; j < nTraces; j++) {
            diff_score = (float) check_trace(&traces[j], dict[i], ctx);
            if ( diff_score > DIFF_THRESHOLD ) {
                ok = false;
                break;
            }
        }
        diff_score /= nTraces;
#pragma omp critical
{
        if (diff_score < min_score)
        {
            min_score = diff_score;
            most_probable_pwd = dict[i];
        }
        if (ok)
            printf("%s (score %.2f)\n", dict[i], diff_score);
}    
    }

    printf("\n-----\nMost probable password (score %.2f): %s\n", min_score, most_probable_pwd);

    end:
    if (fp) {fclose(fp);}
    free(Talloc);
    free(dict);
    if (traces) {free(traces);}
    if (ctx) {free(ctx);}

    return 0;
}