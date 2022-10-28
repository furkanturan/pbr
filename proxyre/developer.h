#ifndef DEVELOPER_H_
#define DEVELOPER_H_

#include "pre.h"

void dev_init();

int dev_create_accelerator(
    plaintext_t plaintext);

int dev_encrypt(
    l2_ciphertext_t ciphertext, 
	plaintext_t plaintext);

int dev_apply_csp_token(
    l2_ciphertext_t rere_ciphertext, 
    l2_ciphertext_t re_ciphertext);

#endif