/*
    bfe.c  uses the boringSSL library to encrypts/decrypts files.  

Boring File Encryption (bfe) is a work of the United States Government. It 
is in the public domain and open source. There is no copyright. You are free
to do anything you want with this source but we like to get credit for our work
and we would like you to offer your changes so we can possibly add them
to the "official" version. Please see CONTRIBUTING.md for information on
how you can contribute to the project.

*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>          // cat /usr/include/sysexits.h to see exit codes
#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/ecdsa.h>
#include <openssl/ec_key.h>
#include <openssl/hmac.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include "../crypto/fipsmodule/rand/internal.h"
#include "../crypto/internal.h"

static void hexdump(const void *a, size_t len) {
  const unsigned char *in = (const unsigned char *)a;
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }

  printf("\n");
}

int main(int argc, char **argv) {
    int FIPS_mode_results = -1;
    int eflag = 0;
    int dflag = 0;
    int hflag = 0;
    char *input_file_name = NULL;
    char *output_file_name = NULL;
    char *password = NULL;
    char password_double[32];
    int c;
    int args_processed = 0;
        
    while ((c = getopt (argc, argv, ":hedp:i:o:")) != -1) {
        args_processed = 1;
        switch (c) {
            case 'e':
                eflag = 1;
                break;
            case 'd':
                dflag = 1;
                break;
            case 'h':
                hflag = 1;
                break;
            case 'i':
                input_file_name = optarg;
                break;
            case 'o':
                output_file_name = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case '?':
                printf("Unknown option: %c\n", optopt);
                return EX_USAGE;
            case ':':
                printf("Missing arg for parameter %c\n", optopt);
                return EX_USAGE;
        }
    }

    if (hflag || args_processed == 0) {
        printf("help for boring file encryption (BFE):\n");
        printf("\t-e encrypt\n");
        printf("\t-d decrypt\n");
        printf("\t-p password, must be 16 characters\n");
        printf("\t-i input_file_name\n");
        printf("\t-o output_file_name\n");
        
        return 0;
    }
    
    if (password == NULL) {
        printf("password with -p option must be specified");
        return EX_USAGE;
    } else {
        if (strlen(password) != 16) {
            printf("password must be 16 characters exactly!\n");
            return EX_USAGE;
        } else {
            // password is 16 characters, now we must double it because AES 256 requires 32 character password
            strcpy(password_double, password);
            strcpy(password_double + 16, password);
        }
    }

    
    if (eflag || dflag) {
        if (output_file_name == NULL) {
                printf("-o output file must be specified\n");
                return EX_USAGE;
        }
        if (output_file_name != NULL && access(output_file_name, F_OK) == 0) {
            printf("ouput file exists bfe has stopped\n");
            return EX_USAGE;
        }
        if (input_file_name == NULL) {
            printf("-i input file must be specified\n");
            return EX_USAGE;
        }
        if (input_file_name != NULL && output_file_name != NULL && strcmp(input_file_name, output_file_name) == 0) {
            printf("the input file can not be equal to the output file name\n");
            return EX_USAGE;
        }
        if (input_file_name != NULL && access(input_file_name, R_OK) != 0) {
            printf("input file doesn't exist or is not readable\n");
            return EX_NOINPUT;
        }
    } else if (eflag && dflag) {
        printf("both -e and -d were specified, do you want to encrypt or decrypt?  Please specify only -e or -d not both!");
        return EX_USAGE;
    } 
    else {
        printf("-e or -d must be specified\n");
        return EX_USAGE;
    }
    
    AES_KEY aes_key;
    uint8_t aes_iv[16];
    size_t out_len;
    FILE *f = NULL;
    FILE *f_out = NULL;
    long fsize;
    long sizeof_output;
    uint8_t *output;

    CRYPTO_library_init();
    FIPS_mode_results = FIPS_mode();
    if (FIPS_mode_results != 1) {
        printf("FIPS mode must be enabled to use this library for government work\n");
        return EX_USAGE;
    }
    else {
        printf("FIPS mode is enabled for boringSSL library, government approved encryption will continue\n");
                
        uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
        //uint8_t nonce[12];
        OPENSSL_memset(nonce, 0, sizeof(nonce));
        EVP_AEAD_CTX aead_ctx;
        if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_256_gcm(), (uint8_t *)password_double,
            strlen(password_double), 0, NULL)) {
            printf("EVP_AEAD_CTX_init failed\n");
            return EX_NOPERM;
        }       
        
        if (eflag) {
            if (input_file_name != NULL) {
                f = fopen(input_file_name, "rb");
            }
            if (f == NULL) {
                printf("On encryption unable to open input_file_name, BFE stops\n");
                return EX_NOPERM;
            }
            size_t bytes_read;
            size_t buffer_size = 1000000 * 100;   // 100 MB buffer
            char *buffer = malloc(buffer_size);
            char *kPlaintext = NULL;
            char *temp_kPlaintext = NULL;
            size_t size_of_kPlainText = 0;
            
            while (!feof(f)) {
                bytes_read = fread(buffer, 1, buffer_size, f);
                if (bytes_read > 0) {
                    if (kPlaintext == NULL) { // first time being allocated
                        kPlaintext = malloc(bytes_read);
                        memcpy(kPlaintext, buffer, bytes_read);
                        size_of_kPlainText = bytes_read;
                    } else { // we need to be careful and do some reallocation
                        temp_kPlaintext = kPlaintext;
                        kPlaintext = malloc(size_of_kPlainText + bytes_read);
                        memmove(kPlaintext, temp_kPlaintext, size_of_kPlainText);
                        memcpy(kPlaintext + size_of_kPlainText, buffer, bytes_read);
                        size_of_kPlainText = size_of_kPlainText + bytes_read;
                    }
                }   
            } 
            fclose(f);
            sizeof_output = size_of_kPlainText * 2;
            output = malloc(sizeof_output);
            f_out = fopen(output_file_name, "wb");
            if (f_out == NULL) {
                printf("On encryption unable to open output_file_name, BFE stops\n");
                return EX_NOPERM;
            }
            if (!EVP_AEAD_CTX_seal(&aead_ctx, output, &out_len, sizeof_output, nonce,
                EVP_AEAD_nonce_length(EVP_aead_aes_256_gcm()),
                (const uint8_t *)kPlaintext, size_of_kPlainText, NULL, 0)) {
                    printf("AES-GCM encrypt failed\n");
                    return EX_NOPERM;
                }        
            fwrite(output, 1, out_len, f_out);
            fclose(f_out);            
            EVP_AEAD_CTX_cleanup(&aead_ctx);
            free(kPlaintext);
            free(output);
        } else if (dflag) {
            f = fopen(input_file_name, "rb");
            if (f == NULL) {
                printf("On decryption unable to open input_file_name, BFE stops\n");
                return EX_NOPERM;
            }
            fseek(f, 0, SEEK_END);
            fsize = ftell(f);
            fseek(f, 0, SEEK_SET);

            char *kPlaintext = malloc(fsize + 1);
            fread(kPlaintext, fsize, 1, f);
            fclose(f);
        
            sizeof_output = fsize * 2 * sizeof(uint8_t);
            output = malloc(sizeof_output);
            if (!EVP_AEAD_CTX_open(&aead_ctx, output, &out_len, sizeof_output, nonce,
                EVP_AEAD_nonce_length(EVP_aead_aes_256_gcm()),
                (const uint8_t *)kPlaintext, fsize, NULL, 0)) {
                    printf("AES-GCM decrypt failed, maybe wrong password?\n");
                    return EX_NOPERM;
            }
            f = fopen(output_file_name, "wb");
            if (f == NULL) {
                printf("On decryption unable to open output_file_name, BFE stops\n");
                return EX_NOPERM;
            }
            fwrite(output, out_len, 1, f);
            fclose(f);
            printf("out_len: %zu fsize: %ld\n", out_len, fsize);

            EVP_AEAD_CTX_cleanup(&aead_ctx);
            free(kPlaintext);
            free(output);
        }
    }
    
  return 0;    
}