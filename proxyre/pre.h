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
 
#ifndef PRE_H
#define PRE_H

#include <assert.h>
#include <stdio.h>
#include <limits.h>

#include <relic.h>
#include <relic_core.h>
#include <relic_types.h>
#include <relic_bn.h>
#include <relic_ec.h>
#include <relic_md.h>
#include <relic_pc.h>

////////////////////////////////////////
//         Struct definitions         //
////////////////////////////////////////

/**
 *  PRE public parameters
 *
 *  These must be shared by public/private keypairs that are
 *  encrypting/decrypting the same messages.
 */
struct pre_params_s {
  g1_t g1;     // generator for G1
  g2_t g2;     // generator for G2
  gt_t Z;      // Z = e(g1,g2)
  bn_t g1_ord; // order of g1
};
typedef struct pre_params_s *pre_rel_params_ptr;
typedef struct pre_params_s parameters_t[1];

/**
 *  PRE secret key
 *
 *  a_inv is cached in the secret key to avoid redundant computation.
 */
struct pre_sk_s {
  bn_t a;     // secret factor a
  bn_t a_inv; // 1/a mod n (n = order of g1)
};
typedef struct pre_sk_s *pre_rel_sk_ptr;
typedef struct pre_sk_s secretkey_t[1];

/**
 *  PRE public key
 */
struct pre_pk_s {
  g1_t pk1; // public key g1^a
  g2_t pk2; // public key g2^a
};
typedef struct pre_pk_s *pre_rel_pk_ptr;
typedef struct pre_pk_s publickey_t[1];

/**
 * PRE re-encryption token
 */
struct pre_token_s {
  g1_t token;
};
typedef struct pre_token_s *pre_token_ptr;
typedef struct pre_token_s pre_token_t[1];

/**
 * PRE re-encryption token
 */
struct pre_retoken_s {
  g2_t token;
};
typedef struct pre_retoken_s *pre_retoken_ptr;
typedef struct pre_retoken_s rekey_t[1];


/**
 * PRE plaintext
 */
struct pre_plaintext_s {
  gt_t msg;
};
typedef struct pre_plaintext_s *pre_rel_plaintext_ptr;
typedef struct pre_plaintext_s plaintext_t[1];

/**
 * PRE ciphertext that was encrypted directly a public key
 */
struct pre_ciphertext_s {
  gt_t c1; // ciphertext part 1 in GT
  g1_t c2; // ciphertext part 2 in G1
};
typedef struct pre_ciphertext_s *pre_rel_ciphertext_ptr;
typedef struct pre_ciphertext_s l2_ciphertext_t[1];

/**
 * PRE ciphertext that was re-encrypted to a second public key
 */
struct pre_re_ciphertext_s {
  gt_t c1; // ciphertext part 1 in GT
  gt_t c2; // ciphertext part 2 in GT
};
typedef struct pre_re_ciphertext_s *pre_rel_re_ciphertext_ptr;
typedef struct pre_re_ciphertext_s l1_ciphertext_t[1];

////////////////////////////////////////
//      Initialization Functions      //
////////////////////////////////////////

/**
 * Initializes the PRE library
 *
 * *** Must be called before first use! ***
 *
 * @return RLC_OK if ok else RLC_ERR
 */
int pre_init();

/**
 * Cleans up PRE library state
 *
 * @return RLC_OK if ok else RLC_ERR
 */
int pre_cleanup();

////////////////////////////////////////
//      Key generation Functions      //
////////////////////////////////////////

/**
 * Generates suitable public parameters for the scheme
 *
 * @param params the resulting public parameters
 * @return RLC_OK if ok else RLC_ERR
 */
int pre_generate_params(parameters_t params);

/**
 * Generates a random secret key
 *
 * @param sk the resulting secret key
 * @param params the public parameters
 * @return RLC_OK if ok else RLC_ERR
 */
int pre_generate_sk(secretkey_t sk, parameters_t params);

/**
 * Derives the public key corresponding to the given secret key
 *
 * @param pk the resulting public key
 * @param params the public parameters
 * @param sk the secret key
 * @return RLC_OK if ok else RLC_ERR
 */
int pre_derive_pk(publickey_t pk, parameters_t params, secretkey_t sk);

#endif