#ifndef SSS_SHARE_METH_H
#define SSS_SHARE_METH_H
#include "share.h"

/**
 * The prototype of a function that creates a new number object.
 *
 * @param [in]  len  The length of the secret in bytes.
 * @param [out] num  The new number object.
 * @return  ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
typedef SHARE_ERR (SHARE_NUM_NEW_FUNC)(uint16_t len, void **num);
/**
 * The prototype of a function that frees a number object.
 *
 * @param [in] num  The number object.
 */
typedef void (SHARE_NUM_FREE_FUNC)(void *num);
/**
 * The prototype of a function that decodes data into a number object.
 * The data is assumed to be big-endian bytes.
 *
 * @param [in] data  The data to be decoded.
 * @param [in] len   The length of the data to be decoded.
 * @param [in] num   The number object.
 * @return  ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
typedef SHARE_ERR (SHARE_NUM_FROM_BIN_FUNC)(const uint8_t *data, uint16_t len,
    void *num);
/**
 * The prototype of a function that encodes a number object into data.
 * The data is assumed to be big-endian bytes.
 *
 * @param [in] num   The number object.
 * @param [in] data  The data to hold the encoding.
 * @param [in] len   The number of bytes that data can hold.
 * @return  PARAM_BAD_LEN when encoding is too long for data.<br>
 *          NONE otherwise.
 */
typedef SHARE_ERR (SHARE_NUM_TO_BIN_FUNC)(void *num, uint8_t *data,
    uint16_t len);
/**
 * The prototype of a function that calculates the y value of a split.
 * y = x^0.a[0] + x^1.a[1] + ... + x^(parts-1).a[parts-1]
 *
 * @param [in] prime  The prime as a number object.
 * @param [in] parts  The number of parts that are required to recalcuate
 *                    secret.
 * @param [in] a      The array of coefficients.
 * @param [in] x      The x value as a number object.
 * @param [in] y      The y value as a number object.
 * @return  ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
typedef SHARE_ERR (SHARE_SPLIT_FUNC)(void *prime, uint8_t parts, void **a,
    void *x, void *y);
/**
 * The prototype of a function that calculates the secret from splits.
 * secret = sum of (i=0..parts-1) y[i] *
 *          product of (j=0..parts-1) x[j] / (x[j] - x[i]) where j != i
 *
 * @param [in] prime   The prime as a number object.
 * @param [in] parts   The number of parts that are required to recalcuate
 *                     secret.
 * @param [in] x       The array of x values as number objects.
 * @param [in] y       The array of y values as number objects.
 * @param [in] secret  The calculated secret as a number object.
 * @return  ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
typedef SHARE_ERR (SHARE_JOIN_FUNC)(void *prime, uint8_t parts, void **x,
    void **y, void *secret);

/** The data structure of an implementation method. */
typedef struct share_meth_st
{
    /** The name of the implementation method. */
    char *name;
    /** The maximim length of the secret. No maximum: 0. */
    uint16_t len;
    /** The number of parts that the implementation supports. Any: 0. */
    uint8_t parts;
    /** Creates a new number object. */
    SHARE_NUM_NEW_FUNC *num_new;
    /** Frees a number object. */
    SHARE_NUM_FREE_FUNC *num_free;
    /** Decodes data into a number object. */
    SHARE_NUM_FROM_BIN_FUNC *num_from_bin;
    /** Encodes a number object into data. */
    SHARE_NUM_TO_BIN_FUNC *num_to_bin;
    /** Calculates the y value of a split. */
    SHARE_SPLIT_FUNC *split;
    /** Calculates the secret from splits. */
    SHARE_JOIN_FUNC *join;
} SHARE_METH;

/* The generic implementation that uses OpenSSL. */
SHARE_ERR share_openssl_num_new(uint16_t len, void **num);
void share_openssl_num_free(void *num);
SHARE_ERR share_openssl_num_from_bin(const uint8_t *data, uint16_t len,
    void *num);
SHARE_ERR share_openssl_num_to_bin(void *num, uint8_t *data, uint16_t len);
SHARE_ERR share_openssl_split(void *prime, uint8_t parts, void **a, void *x,
    void *y);
SHARE_ERR share_openssl_join(void *prime, uint8_t parts, void **x, void **y,
    void *secret);
#endif /* SSS_SHARE_METH_H */
