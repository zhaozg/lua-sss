#ifndef SHARE_H
#define SHARE_H

#include <stdint.h>

/** The maximum number of parts able to be required to reconstruct secret. */
#define SHARE_PARTS_MAX			16

/** Error codes. */
typedef enum share_err_en {
    /** No error. */
    NONE		= 0,
    /** Operation failed to produce a valid result. */
    FAILED		= 1,
    /** The data to work on is invalid for the operation. */
    INVALID_DATA	= 2,
    /** A parameter was a NULL pointer. */
    PARAM_NULL		= 10,
    /** A parameter was a bad value. */
    PARAM_BAD_VALUE	= 11,
    /** A parameter was a bad length. */
    PARAM_BAD_LEN	= 12,
    /** No result was found. */
    NOT_FOUND		= 20,
    /** Dynamic memory allocation error. */
    ALLOC		= 30,
    /** Random number generation failure. */
    RANDOM		= 40,
    /** Value has no modular inverse. */
    MOD_INV             = 41
} SHARE_ERR;

/** The structure for splitting and joining */
typedef struct share_st SHARE;

SHARE_ERR SHARE_new(uint16_t len, uint8_t parts, SHARE **share);
void SHARE_free(SHARE *share);

SHARE_ERR SHARE_get_len(SHARE *share, uint16_t *len);
SHARE_ERR SHARE_get_num(SHARE *share, uint16_t *num);
SHARE_ERR SHARE_get_impl_name(SHARE *share, char **name);

SHARE_ERR SHARE_split_init(SHARE *share, uint8_t *secret);
SHARE_ERR SHARE_split(SHARE *share, uint8_t *data);

SHARE_ERR SHARE_join_init(SHARE *share);
SHARE_ERR SHARE_join_update(SHARE *share, uint8_t *data);
SHARE_ERR SHARE_join_final(SHARE *share, uint8_t *secret);


SHARE_ERR SHARE_random(unsigned char *a, int len);

#endif

