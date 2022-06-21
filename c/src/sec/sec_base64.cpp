/**
    @file sec_base64.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

static size_t b64_calc_dec_len(const char* p_b64_in) 
{
    //Calculates the length of a decoded string
   size_t len = strlen(p_b64_in),
   	padding = 0;

	if (p_b64_in[len - 1] == '=' && p_b64_in[len - 2] == '=') //last two chars are =
    	padding = 2;
	else if (p_b64_in[len - 1] == '=') //last char is =
    	padding = 1;

	return (len * 3) / 4 - padding;
}

int32_t b64_encode(const uint8_t *p_buf, size_t length, char **pp_b64_text)
{
    //Encodes a binary safe base 64 string
    BIO *p_bio, *p_b64;
	BUF_MEM *p_buf_mem;
    int32_t ret = ERROR_;

	p_b64 = BIO_new(BIO_f_base64());
	p_bio = BIO_new(BIO_s_mem());
	p_bio = BIO_push(p_b64, p_bio);

	BIO_set_flags(p_bio, BIO_FLAGS_BASE64_NO_NL);   //Ignore newlines - write everything in one line
	BIO_write(p_bio, p_buf, length);
    (void)BIO_flush(p_bio);
	BIO_get_mem_ptr(p_bio, &p_buf_mem);
    (void)BIO_set_close(p_bio, BIO_NOCLOSE);
	BIO_free_all(p_bio);

    *pp_b64_text = (*p_buf_mem).data;

    ret = SUCCESS_;

	return (ret); //success
}
int32_t b64_decode(char *p_b64_msg, uint8_t **pp_buf, size_t *p_length)
{
    //Decodes a base64 encoded string
    BIO *p_bio, *p_b64;
	size_t decode_len;
    int32_t ret = ERROR_;

    decode_len = b64_calc_dec_len(p_b64_msg);
    *pp_buf = (unsigned char*)MALLOC_M(decode_len + 1);
    (*pp_buf)[decode_len] = '\0';

	p_bio = BIO_new_mem_buf(p_b64_msg, -1);
	p_b64 = BIO_new(BIO_f_base64());
	p_bio = BIO_push(p_b64, p_bio);

	BIO_set_flags(p_bio, BIO_FLAGS_BASE64_NO_NL);   //Do not use newlines to flush buffer
    *p_length = BIO_read(p_bio, *pp_buf, STRLEN_M(p_b64_msg));
	ASSERT_M(*p_length == decode_len);   //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(p_bio);

	ret = SUCCESS_;

	return (ret); //success
}
 