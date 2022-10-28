#include "developer.h"

extern parameters_t params;

secretkey_t dev_sk;
publickey_t dev_pk;

void dev_init() {

  pre_generate_sk(dev_sk, params);
  pre_derive_pk  (dev_pk, params, dev_sk);
}

int dev_create_accelerator(plaintext_t plaintext) {
  int result = RLC_OK;

  TRY {
    gt_new(plaintext->msg);
    gt_rand(plaintext->msg);
  }
  CATCH_ANY {
    gt_free(plaintext->msg);
    result = RLC_ERR;
  }

  return result;
}

int dev_encrypt(
    l2_ciphertext_t ciphertext, 
    plaintext_t plaintext) {
   
  // Input:
  //  m
    
  // Output level2:
  //  c = (c1, c2)     c1, c2 \in G
  //       c1 = m*Z^k
  //       c2 = g^(d_priv)k = (d_pub)^k

  int result = RLC_OK;

  bn_t k;

  bn_null(k);

  TRY {
    bn_new(k);

    gt_new(ciphertext->c1);
    g1_new(ciphertext->c2);

    assert(ciphertext);
    assert(params);
    assert(dev_pk);

    // Compute c1 = m*Z^k

    // random k in Zn
    bn_rand_mod(k, params->g1_ord);
    while (bn_is_zero(k)) {
      bn_rand_mod(k, params->g1_ord);
    }

    // Z^k
    gt_exp(ciphertext->c1, params->Z, k);

    // m*Z^r
    gt_mul(ciphertext->c1, ciphertext->c1, plaintext->msg);
    
    // Compute c2 = g^(d_priv)k = (d_pub)^k  
    g1_mul(ciphertext->c2, dev_pk->pk1, k);

  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(ciphertext->c1);
    g1_null(ciphertext->c2);
  }
  FINALLY {
    bn_free(k);
  }

  return result;
}

int dev_apply_csp_token(
    l2_ciphertext_t rere_ciphertext, 
    l2_ciphertext_t re_ciphertext) {

  // Input level2: 
  //  c1 = m*Z^k
  //  c2 = g^(d_priv)(csp_priv)k

  // Output level2: 
  //  c1 = m*Z^k = c1
  //  c2 = g^(csp_priv)k = c2^(1/csp_priv)k

  int result = RLC_OK;

  TRY {
    assert(rere_ciphertext);
    assert(re_ciphertext);
    
    gt_free(rere_ciphertext->c1);
    g1_free(rere_ciphertext->c2);

    gt_new(rere_ciphertext->c1);
    g1_new(rere_ciphertext->c2);

    gt_copy(rere_ciphertext->c1, re_ciphertext->c1);

    g1_mul(rere_ciphertext->c2, re_ciphertext->c2, dev_sk->a_inv);
  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(rere_ciphertext->c1);
    g1_null(rere_ciphertext->c2);
  }

  return result;
}