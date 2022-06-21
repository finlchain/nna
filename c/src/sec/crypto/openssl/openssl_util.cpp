/**
    @file openssl_util.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

void openssl_handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void openssl_init_v(void)
{
#if (OPENSSL_111 == ENABLED)
    OPENSSL_init();
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111
}

void openssl_get_version(void)
{
    // OPENSSL_VERSION_NUMBER 
    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"OpenSSL Version : %s\n", OpenSSL_version(OPENSSL_VERSION));
}


#if (OPENSSL_111 == ENABLED)
struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};
#endif // OPENSSL_111

//
char *BN_bn2hex_z(const BIGNUM *a)
{
    int i, j, v, z = 1;
    char *buf;
    char *p;
    
    static const char Hex_z[] = "0123456789ABCDEF";

    //DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"a->top(%d)\n", a->top);

    if (BN_is_zero(a))
        return OPENSSL_strdup("0");
#if (OPENSSL_111 == ENABLED)
    buf = (char *)OPENSSL_malloc((size_t)(a->top * BN_BYTES * 2 + 2));
#elif (OPENSSL_102 == ENABLED)
    buf = (char *)OPENSSL_malloc(a->top * BN_BYTES * 2 + 2);
#endif // OPENSSL_111
    if (buf == NULL) {
        BNerr(BN_F_BN_BN2HEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (a->neg)
    {
#if (OPENSSL_111 == ENABLED)
        *p++ = '-';
#elif (OPENSSL_102 == ENABLED)
        *(p++) = '-';
#endif // OPENSSL_111
    }
    if (BN_is_zero(a))
    {
#if (OPENSSL_111 == ENABLED)
        *p++ = '0';
#elif (OPENSSL_102 == ENABLED)
        *(p++) = '0';
#endif // OPENSSL_111
    }
    for (i = a->top - 1; i >= 0; i--) {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8) {
            /* strip leading zeros */
#if (OPENSSL_111 == ENABLED)
            v = (int)((a->d[i] >> j) & 0xff);
            if (z || v != 0) {
                *p++ = Hex_z[v >> 4];
                *p++ = Hex_z[v & 0x0f];
                z = 1;
#elif (OPENSSL_102 == ENABLED)
            v = ((int)(a->d[i] >> (long)j)) & 0xff;
            //DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"z(%d) v(0x%02X)\n", z, v);
            if (z || (v != 0)) {
                *(p++) = Hex_z[v >> 4];
                *(p++) = Hex_z[v & 0x0f];
                z = 1;
#endif // OPENSSL_111
            }
        }
    }
    *p = '\0';
 err:
    return (buf);
}
    
//
EVP_PKEY *EVP_PKEY_new_read_PRIKEY(bool b_enc, char *p_prikey_path)
{
    EVP_PKEY *p_pkey = NULL;
    
    if (b_enc)
    {
        uint8_t *p_dec;

        uint8_t *p_pw;
        uint32_t pw_len;
        
        p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);

        p_dec = openssl_aes_decrypt_file(p_prikey_path, (uint8_t *)p_pw, pw_len);
        if(p_dec)
        {
            BIO *pri_b = BIO_new_mem_buf((void*)p_dec, STRLEN_M((char *)p_dec));

            if (pri_b)
            {
                p_pkey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

                BIO_free(pri_b);
            }
            
            FREE_M(p_dec);
        }

        FREE_M(p_pw);
    }
    else
    {
        FILE* fp;
        
        fp = fopen (p_prikey_path, "r");
        if (fp)
        {
            p_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

            fclose(fp);
        }
    }

    return (p_pkey);
}

EVP_PKEY *EVP_PKEY_new_read_PUBKEY(char *p_pubkey_path)
{
    EVP_PKEY *p_pkey = NULL;
    FILE *fp;

    fp= fopen(p_pubkey_path, "r");
    if(fp)
    {
        p_pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        
        fclose(fp);
    }
    
    return (p_pkey);
}

int32_t PEM_new_write_PUBKEY(char *p_pubkey_path, EVP_PKEY *pkey)
{
    int32_t ret = ERROR_;
    FILE* fp;
    
    fp = fopen(p_pubkey_path, "w");
    if(!fp) return (ERROR_);

#if 1
    PEM_write_PUBKEY(fp, pkey);
    ret = SUCCESS_;
#else
    do
    {
        BIO *p_outbio = NULL;
        p_outbio = BIO_new_fp(fp, BIO_NOCLOSE);
        
        if (p_outbio)
        {
            if(!PEM_write_bio_PUBKEY(p_outbio, pkey))
            {
                DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"Error writing public key data in PEM format\n");
                break;
            }

            ret = SUCCESS_;
            
            BIO_free(p_outbio);
        }
    } while(0);
#endif

    fclose(fp);

    return (ret);
}

int32_t PEM_new_write_PRIKEY(char *p_prikey_path, EVP_PKEY *pkey)
{
    FILE* fp;
    
    fp = fopen(p_prikey_path, "w");
    if(!fp) return (ERROR_);
    
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL);
    fclose(fp);
    
    return (SUCCESS_);
}

int32_t PEM_write_raw_PUBKEY(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"p_pubkey_path (%s)\n", p_pubkey_path);

    if(p_pubkey[0] == PUBKEY_DELIMITER_25519) // 25519
    {
        uint8_t *p_ed_pubkey;

        p_ed_pubkey = &p_pubkey[1];
        ret = openssl_ed_pubkey_hex2pem(p_pubkey_path, (uint8_t *)p_ed_pubkey);
    }
    else if(p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP) // EC Uncompress
    {
        ret = openssl_ec_pubkey_hex2pem(p_pubkey_path, (uint8_t *)p_pubkey);
    }
    else if(p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP || p_pubkey[0] == PUBKEY_DELIMITER_EC_COMP_EVEN || p_pubkey[0] == PUBKEY_DELIMITER_EC_COMP_ODD)
    {
        char comp_pubkey_str[COMP_PUBKEY_STR_SIZE];
        char uncomp_pubkey_str[UNCOMP_PUBKEY_STR_SIZE];
        char uncomp_pubkey[UNCOMP_PUBKEY_SIZE];
        
        util_hex2str_temp(p_pubkey, COMP_PUBKEY_SIZE, comp_pubkey_str, COMP_PUBKEY_STR_SIZE, false);
        openssl_ec_pubkey_decompress(comp_pubkey_str, uncomp_pubkey_str);
        util_str2hex_temp(uncomp_pubkey_str, (unsigned char *)uncomp_pubkey, UNCOMP_PUBKEY_SIZE, false);

        ret = openssl_ec_pubkey_hex2pem(p_pubkey_path, (uint8_t *)uncomp_pubkey);
    }
    else
    {
        ASSERT_M(0);
    }

    return (ret);
}

// x9_63_kdf = kdf2
int openssl_kdf2(const EVP_MD *md, const uint8_t *p_share, uint32_t share_len, const uint8_t *p_kdp, size_t kdp_len, uint32_t key_len, uint8_t *p_key)
{                   
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t counter[4] = {0, 0, 0, 1};
    uint8_t dgst[EVP_MAX_MD_SIZE];
    uint32_t dgst_len;
    int32_t rlen = (int32_t)key_len;
    unsigned char *pp;

    pp = p_key;

    if (key_len > (uint32_t)(EVP_MD_size(md)*255))
    {
        fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
        goto end;
    }

    while (rlen > 0)
    {
#if (OPENSSL_111 == ENABLED)
        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            goto end;
        }
#elif (OPENSSL_102 == ENABLED)
        ctx = (EVP_MD_CTX *)MALLOC_M(sizeof(EVP_MD_CTX));
        if (!ctx)
        {
            goto end;
        }

        EVP_MD_CTX_init(ctx);
#endif // OPENSSL_111

        if (!EVP_DigestInit(ctx, md))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (!EVP_DigestUpdate(ctx, p_share, share_len))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (!EVP_DigestUpdate(ctx, counter, 4))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (kdp_len && p_kdp)
        {
            if (!EVP_DigestUpdate(ctx, p_kdp, kdp_len))
            {
                fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
                goto end;
            }
        }

        if (!EVP_DigestFinal(ctx, dgst, &dgst_len))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

#if (OPENSSL_102 == ENABLED)
        EVP_MD_CTX_cleanup(ctx);
#endif // OPENSSL_102

        MEMCPY_M(pp, dgst, key_len>=dgst_len ? dgst_len:key_len);

        rlen -= dgst_len;
        pp += dgst_len;
        counter[3]++;
    }

    ret = 1;

    end:
    if (ctx)
    {
#if (OPENSSL_111 == ENABLED)
        EVP_MD_CTX_free(ctx);
#elif (OPENSSL_102 == ENABLED)
        FREE_M(ctx);
#endif // OPENSSL_111
    }
    
    return ret;
}

uint32_t openssl_aes_cbc_encrypt(const uint8_t *plaintext, int32_t plaintext_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        //openssl_handleErrors();
        return (0);
    }
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        //openssl_handleErrors();
        return (0);
    }
    
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        //openssl_handleErrors();
        return (0);
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

uint32_t openssl_aes_cbc_decrypt(const uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        //openssl_handleErrors();
        return (0);
    }

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        //openssl_handleErrors();
        return (0);
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int32_t openssl_aes_encrpt_file(char *p_src_path, char *p_dst_path, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;

    uint8_t *p_plane, *p_enc;
    uint32_t plane_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_plane = (uint8_t *)util_file_r(p_src_path, &plane_len);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"plane_len: %d\n", plane_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%s\n", p_plane);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file plane", (uint8_t *)p_plane, plane_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    enc_len = plane_len + 1 + AES_BLOCK_SIZE;
    p_enc = (uint8_t *)MALLOC_M(enc_len);
    MEMSET_M(p_enc, 0, enc_len);
    
    enc_len = openssl_aes_cbc_encrypt(p_plane, plane_len, p_key, p_iv, p_enc);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    util_hex_file_wb(p_dst_path, p_enc, enc_len);

    FREE_M(p_plane);
    FREE_M(p_enc);

    ret = SUCCESS_;

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (ret);
}

uint8_t *openssl_aes_decrypt_file(char *p_src_path, uint8_t *p_seed, uint32_t seed_len)
{
    uint8_t *p_plane, *p_enc;
    uint32_t plane_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_enc = (uint8_t *)util_hex_file_rb(p_src_path, &enc_len);

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    plane_len = enc_len + 1;
    p_plane = (uint8_t *)MALLOC_M(plane_len);
    MEMSET_M(p_plane, 0x00, plane_len);

    plane_len = openssl_aes_cbc_decrypt(p_enc, enc_len, p_key, p_iv, p_plane);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"plane_len: %d\n", plane_len);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", p_plane);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "aes_dec", (uint8_t *)p_plane, plane_len);

    FREE_M(p_enc);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (p_plane);
}

int32_t openssl_aes_encrypt_pw(char *p_seed_path, uint8_t *p_pw, uint32_t pw_len, char *p_dst_path)
{
    int32_t ret = ERROR_;

    uint8_t *p_seed, *p_enc;
    uint32_t seed_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    // Seed
    p_seed = (uint8_t *)util_file_r(p_seed_path, &seed_len);
    if (!p_seed)
    {
        return (ret);
    }

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"seed_len: %d\n", seed_len);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"seed : %s\n", p_seed);

    // Password
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"pw_len: %d\n", pw_len);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"pw : %s\n", p_pw);

    // Key & IV
    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    // Encryption
    enc_len = pw_len + AES_BLOCK_SIZE;
    p_enc = (uint8_t *)MALLOC_M(enc_len);
    MEMSET_M(p_enc, 0, enc_len);
    
    enc_len = openssl_aes_cbc_encrypt((uint8_t *)p_pw, pw_len, p_key, p_iv, p_enc);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    // Write File
    util_hex_file_wb(p_dst_path, p_enc, enc_len);

    FREE_M(p_seed);
    FREE_M(p_enc);

    ret = SUCCESS_;

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (ret);
}

uint8_t *openssl_aes_decrypt_pw(char *p_seed_path, char *p_src_path, uint32_t *p_pw_len)
{
    uint8_t *p_seed, *p_enc, *p_pw;
    uint32_t seed_len, enc_len;
    char seed_path_def[] = "./../../conf/pw/db/me/seed";
    char src_path_def[] = "./../../conf/pw/db/me/pw_maria.fin";

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    *p_pw_len = 0;

    if (!p_seed_path)
    {
        p_seed_path = seed_path_def;
    }

    if (!p_src_path)
    {
        p_src_path = src_path_def;
    }
    
    // Seed
    p_seed = (uint8_t *)util_file_r(p_seed_path, &seed_len);
    if (!p_seed)
    {
        return (NULL);
    }

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"seed_len: %d\n", seed_len);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"seed : %s\n", p_seed);
    
    // Read Encryption
    p_enc = (uint8_t *)util_hex_file_rb(p_src_path, &enc_len);

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    *p_pw_len = enc_len + 1;
    p_pw = (uint8_t *)MALLOC_M(*p_pw_len);
    MEMSET_M(p_pw, 0x00, *p_pw_len);

    *p_pw_len = openssl_aes_cbc_decrypt(p_enc, enc_len, p_key, p_iv, p_pw);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"pw_len: %d\n", *p_pw_len);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", p_pw);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "aes_dec", (uint8_t *)p_pw, *p_pw_len);

    p_pw[*p_pw_len] = '\0';

    FREE_M(p_enc);
    FREE_M(p_seed);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (p_pw);
}

int32_t openssl_sha256(uint8_t *hash, uint8_t *data, uint32_t data_len)
{
   DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"(%s)\n",  __FUNCTION__);

   DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"data : ", data, data_len);

   SHA256_CTX sha256;
   SHA256_Init(&sha256);
   SHA256_Update(&sha256, data, data_len);
   SHA256_Final(hash, &sha256);

   return (SUCCESS_);
}

int32_t openssl_sha256_file(char* path, uint8_t *output)
{   
    int32_t ret = ERROR_;
    FILE *file = fopen(path, "rb");
    if (!file) return (ret);

    do
    {
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int bufSize = 32768;
        char* buffer = (char *)MALLOC_M(bufSize);
        if (!buffer) break;
        int bytesRead = 0;
        while ((bytesRead = util_fread(buffer, 1, bufSize, file)))
        {
            SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(output, &sha256);
        //sha256_hash_string(hash, output);
        
        FREE_M(buffer);
        ret = SUCCESS_;
        
    }while(0);
    
    fclose(file);
    
    return (ret);
} 

