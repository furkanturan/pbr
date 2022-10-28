#ifndef CSP_H_
#define CSP_H_

#include "pre.h"

void csp_init();

int csp_apply_retoken(
    l1_ciphertext_t re_ciphertext, 
    rekey_t token, 
    l2_ciphertext_t ciphertext);

#endif