#include "ttp.h"

parameters_t params;

secretkey_t csp_sk;
extern publickey_t csp_pk;
extern publickey_t fpga_pk;
extern publickey_t dev_pk;

void ttp_init() {

  pre_generate_params(params);  
  pre_generate_sk(csp_sk, params);
  pre_derive_pk  (csp_pk, params, csp_sk); 
}

int tpp_apply_csp_token(
    l2_ciphertext_t re_ciphertext, 
    l2_ciphertext_t ciphertext) {

  // Input level2: 
  //  c1 = m*Z^k
  //  c2 = g^(d_priv)k = (d_pub)^r

  // Output level2: 
  //  c1 = m*Z^k = c1
  //  c2 = g^(d_priv)(csp_priv)k = c2^(csp_priv)

  int result = RLC_OK;

  TRY {
    assert(re_ciphertext);
    assert(ciphertext);
    
    gt_free(re_ciphertext->c1);
    g1_free(re_ciphertext->c2);

    gt_new(re_ciphertext->c1);
    g1_new(re_ciphertext->c2);

    gt_copy(re_ciphertext->c1, ciphertext->c1);
    g1_mul(re_ciphertext->c2, ciphertext->c2, csp_sk->a);
  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(re_ciphertext->c1);
    g1_null(re_ciphertext->c2);
  }

  return result;
}

int ttp_generate_fpga_token(
    rekey_t token) {

  // Output:
  //  token = g^(fpga_priv)/(csp_priv)
  //        = fpga_pub^(1/csp_priv)

  int result = RLC_OK;

  g2_null(token->token);
  TRY {
    assert(token);
    assert(params);
    assert(csp_sk);
    assert(fpga_pk);

    g2_new(token->token);

    g2_mul(token->token, fpga_pk->pk2, csp_sk->a_inv);
  }
  CATCH_ANY {
    result = RLC_ERR;
    g2_null(token->token);
  };

  return result;
}