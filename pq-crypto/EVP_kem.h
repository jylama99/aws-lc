//
// Created by lamjyoti on 8/11/2021.
//

#ifndef AWSLC_EVP_KEM_H
#define AWSLC_EVP_KEM_H

#include "EVP_pq_constants.h"

/*************************************************
* Name: pq_kem
*
* Description: Keeps track of pq algorithim specifc
* constants which are length of public key, private key,
* cipher text, and shared secret. Also contains pointers
* to the specifc algorithms required.
*
*
**************************************************/

struct pq_kem {
  // name of pq algorithm specifc KEM
  const char *name;
  // stores the pq algorithm specifc public key memory size
  const uint16_t public_key_length;
  // stores the pq algorithm specifc private key memory size
  const uint16_t private_key_length;
  // stores the pq algorithm specifc shared secrect memory size
  const uint16_t shared_secret_key_length;
  // stores the pq algorithm specifc ciphertext memory size
  const uint16_t ciphertext_length;

  /* NIST Post Quantum KEM submissions require the following API for compatibility */
  int (*generate_keypair)(OUT uint16_t *public_key, OUT uint16_t *private_key);
  int (*encapsulate)(OUT uint16_t *ciphertext, OUT uint16_t *shared_secret, IN const uint16_t *public_key);
  int (*decapsulate)(OUT uint16_t *shared_secret, IN const uint16_t *cipher_text, IN const uint16_t *private_key);
};

/*************************************************
* Name: pq_kem_params
*
* Description: Keeps track of the actual keys and
* secrets that are pq algorithim specifc.
* They are public key, private key,
* cipher text, and shared secret. Also points
* to the algorithm specifc pq_kem struct
*
*
**************************************************/

struct pq_kem_params {
  const struct s2n_kem *kem;
  uint32_t *public_key;
  uint32_t *private_key;
  uint32_t *ciphertext;
  uint32_t *shared_secret;
};

/*************************************************
* Name: pq_kem_params_alloc
*
* Arguments: pointer to pq_key_params.
* pq_key_params allows access to the lengths and key pointer (output param)
 * of public key, private key, cipher text,
* and shared secrect.
* Description: Allocates the space needed for
* public key, private key, cipher text,
* and shared secrect.
*
* Return EVP_PQ_SUCCESS on success, and EVP_PQ_FAILURE if it fails.
**************************************************/
int pq_kem_params_alloc(pq_kem_params *key_params)

/*************************************************
* Name: pq_kem_params_free
*
* Arguments: pointer to pq_key_params.
* pq_key_params allows access to the lenghts and key pointer (output param)
 * of public key, private key, cipher text,
* and shared secrect.
* Description: Frees space of
* public key, private key, cipher text,
* and shared secrect.
*
* Return EVP_PQ_SUCCESS on success, and EVP_PQ_FAILURE if it fails.
**************************************************/
int pq_kem_params_free(pq_kem_params *key_params)

/*************************************************
* Name: EVP_kem_generate_keypair
*
* Description: Generates a public and private key
*
* Arguments: pq_kem_params
* The following fields of pq_kem_params are used for generate keypair:
* - unsigned char *public_key: pointer to output public key
* (already allocated array of bytes)
* - unsigned char *private_key: pointer to output secret key
* (already allocated array of bytes)
*
* Returns EVP_PQ_SUCCESS on successfully generating key pair,
* return EVP_PQ_FAILURE otherwise and on error
**************************************************/
int EVP_kem_generate_keypair(typedef pq_kem_params *kem_params);


/*************************************************
* Name: EVP_kem_enc
*
* Description: Uses public key to create cipher text and secrect key.
*
* Arguments: pq_kem_params
* The following fields of pq_kem_params are used for encapsualte:
* - unsigned char *cipher_text: pointer to output cipher text
* (already allocated array of bytes)
* - unsigned char *shared_secrect: pointer to output shared secrect
* (already allocated array of bytes)
* - const unsigned char *public_key: pointer to input constant public key
*
* Returns EVP_PQ_SUCCESS on successful encapsulation,
* return EVP_PQ_FAILURE otherwise and on error
**************************************************/
int EVP_kem_encapsulate(typedef pq_kem_params *kem_params);


/*************************************************
* Name: EVP_kem_dec
*
* Description: Generates shared secrect for public key and cipher text
*
* Arguments: pq_kem_params
* The following fields of pq_kem_params are used for decapsulate:
* - unsigned char *shared_secrect: pointer to output shared secret
* (already allocated array of bytes)
* - unsigned char *cipher_text: pointer to input cipher text
* (already allocated array of bytes)
* - const unsigned char *private_key: pointer to input constant private key
*
* Returns EVP_PQ_SUCCESS on successful decapsulation,
* return EVP_PQ_FAILURE otherwise and on error
**************************************************/
int EVP_kem_decapsulate(typedef pq_kem_params *kem_params);




#endif  // AWSLC_EVP_KEM_H
