#ifndef FPGA_H_
#define FPGA_H_

#include "pre.h"

void fpga_init();

int fpga_decrypt(
    plaintext_t plaintext, 
    l1_ciphertext_t ciphertext);

#endif