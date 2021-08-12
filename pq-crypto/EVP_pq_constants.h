//
// Created by lamjyoti on 8/11/2021.
//

#ifndef AWSLC_EVP_PQ_CONSTANTS_H
#define AWSLC_EVP_PQ_CONSTANTS_H


/* TLDR s2n: 0=true, -1=false,
 * TLDR aws-lc: 1=true, 0=false
 * current work around to keep following macros */
#define EVP_PQ_SUCCESS 1
#define EVP_PQ_FAILURE 0


/* SIKE PQ Algorithm Constants */
#define SIKE_P434_R3_PUBLIC_KEY_BYTES 330
#define SIKE_P434_R3_SECRET_KEY_BYTES 374
#define SIKE_P434_R3_CIPHERTEXT_BYTES 346
#define SIKE_P434_R3_SHARED_SECRET_BYTES 16

#endif  // AWSLC_EVP_PQ_CONSTANTS_H
