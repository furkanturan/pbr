/*
 * Copyright (c) 2019, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@inf.ethz.ch>
 *       Hossein Shafagh <shafagh@inf.ethz.ch>
 *       Pascal Fischli <fischlip@student.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pre.h"

////////////////////////////////////////
//      Initialization Functions      //
////////////////////////////////////////

int pre_init() {
  if (core_init() != RLC_OK) {
    core_clean();
    return RLC_ERR;
  }

  if (pc_param_set_any() != RLC_OK) {
    THROW(ERR_NO_CURVE);
    core_clean();
    return RLC_ERR;
  }
  pc_param_print();
  return RLC_OK;
}

int pre_cleanup() {
  core_clean();
  return RLC_OK;
}

////////////////////////////////////////
//      Key generation Functions      //
////////////////////////////////////////

// Helper function to compute 1/a mod m
int mod_inverse(bn_t res, bn_t a, bn_t m) {
  bn_t tempGcd, temp;
  int result = RLC_OK;

  bn_null(tempGcd);
  bn_null(temp);

  TRY {

    bn_new(tempGcd);
    bn_new(temp);

    bn_gcd_ext(tempGcd, res, temp, a, m);
    if (bn_sign(res) == RLC_NEG) {
      bn_add(res, res, m);
    }
  }
  CATCH_ANY { result = RLC_ERR; }
  FINALLY {
    bn_free(tempGcd);
    bn_free(temp);
  }

  return result;
}

int pre_generate_params(parameters_t params) {
  int result = RLC_OK;

  g1_null(params->g1);
  g2_null(params->g2);
  gt_null(params->Z);
  bn_null(params->g1_ord);

  TRY {
    g1_new(params->g1);
    g2_new(params->g2);
    gt_new(params->Z);
    bn_new(params->g1_ord);

    g1_get_gen(params->g1);
    g2_get_gen(params->g2);

    // pairing Z = e(g,g)
    pc_map(params->Z, params->g1, params->g2);

    g1_get_ord(params->g1_ord);
  }
  CATCH_ANY {
    result = RLC_ERR;

    g1_null(params->g1);
    g2_null(params->g2);
    gt_null(params->Z);
    bn_null(params->g1_ord);
  };

  return result;
}

int pre_generate_sk(secretkey_t sk, parameters_t params) {
  int result = RLC_OK;

  bn_null(sk->a);
  bn_null(sk->a_inv);

  TRY {
    bn_new(sk->a);
    bn_new(sk->a_inv);

    // generate a random value, a, as secret key
    bn_rand_mod(sk->a, params->g1_ord);

    // compute 1/a mod n for use later
    mod_inverse(sk->a_inv, sk->a, params->g1_ord);
  }
  CATCH_ANY {
    result = RLC_ERR;

    bn_null(sk->a);
    bn_null(sk->a_inv);
  };

  return result;
}

int pre_derive_pk(publickey_t pk, parameters_t params, secretkey_t sk) {
  int result = RLC_OK;

  g1_null(pk->pk1);
  g2_null(pk->pk2);

  TRY {
    g1_new(pk->pk1);
    g2_new(pk->pk2);

    // compute the public key as 
    // pk1 = g1^a
    // pk2 = g2^a
    g1_mul_gen(pk->pk1, sk->a);
    g2_mul_gen(pk->pk2, sk->a);
  }
  CATCH_ANY {
    result = RLC_ERR;

    g1_null(pk->pk1);
    g2_null(pk->pk2);
  };

  return result;
}