#include "fpga.h"

extern parameters_t params;

secretkey_t fpga_sk;
publickey_t fpga_pk;

void fpga_init() {

  pre_generate_sk(fpga_sk, params);
  pre_derive_pk  (fpga_pk, params, fpga_sk);
}

int fpga_decrypt(
  plaintext_t plaintext, 
  l1_ciphertext_t ciphertext) {

  // Input level1: 
  //  c1 = m*Z^k 
  //  c2 = Z^(fpga_priv)k

  // Output:
  //  m = m*Z^k / (Z^(fpga_priv)k)^(1/fpga_priv)
  //    = c1 / c2^(1/fpga_priv)

  int result = RLC_OK;

  gt_t t0;

  gt_null(t0);
  gt_null(plaintext->msg);

  TRY {
    gt_new(t0);
    gt_new(plaintext->msg);

    assert(params);
    assert(fpga_sk);
    assert(ciphertext);

    if (bn_is_zero(fpga_sk->a_inv)) {
      gt_set_unity(plaintext->msg);
    } else {
      gt_exp(plaintext->msg, ciphertext->c2, fpga_sk->a_inv);
    }

    gt_inv(t0, plaintext->msg);    
    gt_mul(plaintext->msg, ciphertext->c1, t0);
  }
  CATCH_ANY { result = RLC_ERR; }
  FINALLY {
    gt_free(t0);
  }

  return result;
}