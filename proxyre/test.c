#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <gmp.h>
#include "pre.h"

#include "developer.h"
#include "ttp.h"
#include "csp.h"
#include "fpga.h"

int proxy_test() {
  
  rekey_t         token_to_fpga;
  plaintext_t     accelerator;
  plaintext_t     decrypted;
  l2_ciphertext_t cipher_dev;
  l2_ciphertext_t cipher_dev_csp;
  l2_ciphertext_t cipher_csp;
  l1_ciphertext_t cipher_fpga;

////////////////////////////////////////////////////////////////////////////////

  // TTP generates parameters
  ttp_init();

  // Generate keys for dev
  dev_init();

  // Generate keys for csp
  csp_init();

  // Generate keys for fpga
  fpga_init();

////////////////////////////////////////////////////////////////////////////////

  // Developer creates its accelerator
  dev_create_accelerator(accelerator);

  // Developer encrypts the accelerator with its public key
  dev_encrypt(cipher_dev, accelerator);

  // Developer sends the cipher to TTP,
  // TTP applies CSP's token with CSP's secret key
  tpp_apply_csp_token(cipher_dev_csp, cipher_dev);

  // Developer received the cipher back
  // Developer removes its token from the cipher
  // Cipher is ready for CSP now
  // But CSP cannot decrypt, because it does not know the secret key
  dev_apply_csp_token(cipher_csp, cipher_dev_csp);

  // CSP decides for a target FPGA
  // CSP asks from TTP a token for that FPGA
  // CSP can perform this step beforehand for all its FPGAs as well.
  ttp_generate_fpga_token(token_to_fpga);

  // CSP applies the token to the cipher
  // Cipher is ready for FPGA now
  csp_apply_retoken(cipher_fpga, token_to_fpga, cipher_csp);

  // FPGA decrypts the cipher
  fpga_decrypt(decrypted, cipher_fpga);

  if (gt_cmp(accelerator->msg, decrypted->msg) == RLC_EQ) {
    printf("Proxy Encryption-Decrypt OK!\n");
  } else {
    printf("Proxy Encryption-Decrypt FAILED!\n");
  }

  return 0;
}

int main() {
  pre_init();
  proxy_test();
  pre_cleanup();
  return 0;
}
