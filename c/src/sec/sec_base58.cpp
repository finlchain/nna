/**
    @file sec_base58.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#define BASE58_ENC_BUF_SIZE 256

static char _b58_alphabet[]="123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

char *base58_encode(char *p_buf_in)
{
    char *p_enc = NULL;
    int32_t p=0;

    get_current_rss_monitor(DBG_INFO, (char *)"1");
    
    p_enc = (char *)MALLOC_M(BASE58_ENC_BUF_SIZE);
    ASSERT_M (p_enc);
    if (!p_enc)
    {
        return (NULL);
    }
    
    do
    {
        BIGNUM *p_n = NULL;
        
        if ((p_n = BN_new()) == NULL)
        {
            DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"bignum alloc failed\n");
            break;
        }

        do
        {
            BIGNUM *p_bb = NULL;
        	int32_t i, cnt;
        	BN_ULONG base, mod;
            
            BN_hex2bn(&p_n, p_buf_in);
        	if ((p_bb = BN_new()) == NULL)
            {
                DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"bignum alloc failed\n");
        		break;
        	}
            
        	base = STRLEN_M(_b58_alphabet);	/* sizeof is 59, not 58 */
        	BN_set_word(p_bb, base);

            p = BASE58_ENC_BUF_SIZE-1;
            cnt = 0;
        	for (p_enc[p--]=0; BN_cmp(p_n, p_bb) >= 0; )
            {
        		mod = BN_div_word(p_n, base);
                
        		p_enc[p--] = _b58_alphabet[mod];
                cnt++;
                
        		if (p==0)
                {
                    DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"encoding buffer full\n");
        			break;	/* string buffer overflow */
        		}
        	}

            i = BN_get_word(p_n);
        	if (i > 0) {
        		p_enc[p]=_b58_alphabet[i];
        	}

            MEMCPY_M(&p_enc[0], &p_enc[p], cnt);

            BN_free(p_bb);
        } while(0);

    	BN_free(p_n);
    } while(0);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

	return (p_enc);
}

static int32_t strpos(char *haystack, char needle)
{
	char *p;

	for (p=haystack; *p != 0; p++) {
		if (*p == needle) {
			return (p-haystack);
		}
	}
	return -1;	/* not found */
}

/* in case of error, memory is not freed yet */
char *base58_decode(const char *s)
{
    char *p_ret = NULL;
    int32_t ret = SUCCESS_;

    get_current_rss_monitor(DBG_INFO, (char *)"1");
    
    do
    {
        BIGNUM *p_dec;
        
        p_dec = BN_new();
        if (p_dec == NULL)
        {
            break;
        }

        do
        {
            BIGNUM *p_m;

            p_m = BN_new();
            if (p_m == NULL)
            {
                break;
            }

            do
            {
                BIGNUM *p_a;
                int32_t i, k, base=STRLEN_M(_b58_alphabet);

                p_a = BN_new();
                if (p_a == NULL)
                {
                    break;
                }

            	BN_set_word(p_dec, 0);
            	BN_set_word(p_m, 1);
                
            	for (i=STRLEN_M(s)-1; i>=0; i--)
                {
            		BN_copy(p_a, p_m);
            		if ((k=strpos(_b58_alphabet, s[i])) < 0)
                    {
                        ret = ERROR_;
            			break;	/* illegal char in string */
            		}
                    
            		BN_mul_word(p_a, k);
            		BN_add(p_dec, p_dec, p_a);
            		BN_mul_word(p_m, base);
            	}

                if (ret == SUCCESS_)
                {
                    p_ret = BN_bn2hex_z(p_dec);
                }
                
                BN_free(p_a);
            } while(0);
            
            BN_free(p_m);
        } while(0);

        BN_free(p_dec);
    } while(0);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return (p_ret);
}