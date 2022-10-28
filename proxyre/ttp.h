#ifndef TTP_H_
#define TTP_H_

#include "pre.h"

void ttp_init();

int tpp_apply_csp_token(
    l2_ciphertext_t re_ciphertext, 
    l2_ciphertext_t ciphertext);

int ttp_generate_fpga_token(
    rekey_t token);

#endif