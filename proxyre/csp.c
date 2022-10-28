#include "csp.h"

extern parameters_t params;

publickey_t csp_pk;

void csp_init() {
  
}

int csp_apply_retoken(
    l1_ciphertext_t re_ciphertext, 
    rekey_t token, 
    l2_ciphertext_t ciphertext) {

  // Input level2: 
  //  c1 = m*Z^k
  //  c2 = g^(csp_priv)k
  
  // Output level1: 
  //  c1 = m*Z^k = c1
  //  c2 = Z^(fpga_priv)k = e(g^(csp_priv)k, g^(fpga_priv)/(csp_priv))
  //                      = e(c2, token) 

  int result = RLC_OK;

  TRY {
    assert(token);
    assert(re_ciphertext);
    assert(ciphertext);
    
    gt_free(re_ciphertext->c1);
    gt_free(re_ciphertext->c2);
    
    gt_new(re_ciphertext->c1);
    gt_new(re_ciphertext->c2);
    
    gt_copy(re_ciphertext->c1, ciphertext->c1);
    pc_map(re_ciphertext->c2, ciphertext->c2, token->token);
  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(re_ciphertext->c1);
    gt_null(re_ciphertext->c2);
  }

  return result;
}