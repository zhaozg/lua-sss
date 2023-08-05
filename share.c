/*
 * Copyright (c) 2016 Sean Parkinson (sparkinson@iprimus.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <stdlib.h>
#include <string.h>
#include "share_meth.h"

/*** share meths ***/

/** The implementation methods for share operations. */
static SHARE_METH share_meths[] =
{
    /* The generic implementation that uses OpenSSL. */
    { "OpenSSL Generic",
      0, 0,
      share_openssl_num_new, share_openssl_num_free,
      share_openssl_num_from_bin, share_openssl_num_to_bin,
      share_openssl_split, share_openssl_join },
};

/** The number of implementation methods. */
#define SHARE_METHS_NUM ((int8_t)(sizeof(share_meths)/(sizeof(*share_meths))))

/**
 * Retrieves an implementation method that matches the requirements.
 *
 * @param [in]  len    The length of the secret in bits required to be
 *                     supported.
 * @param [in]  parts  The number of parts required to be supported.
 * @param [out] meth   The method that matches the requirements.
 * @return  NOT_FOUND when no available method meets the requirements.<br>
 *          NONE otherwise.
 */
SHARE_ERR share_meths_get(uint16_t len, uint8_t parts, SHARE_METH **meth)
{
    SHARE_ERR err = NOT_FOUND;
    int8_t i;
    SHARE_METH *m = NULL;

    /* Find the first implementation that matches. */
    for (i=0; i<SHARE_METHS_NUM; i++)
    {
        /* Length of zero indicates no restriction. Otherwise it must match.
         * Parts of zero indicates no restriction. Otherwise it must match.
         * Must have at least the flags requested.
         */
        if (((share_meths[i].len == 0) || (share_meths[i].len == len)) &&
            ((share_meths[i].parts == 0) || (share_meths[i].parts == parts)))
        {
            m = &share_meths[i];
            err = NONE;
            break;
        }
    }

    *meth = m;

    return err;
}

/*** private structure */
/** The structure holding primes to use. */
typedef struct share_prime_st
{
    /** The maximum number of bits supported by prime. */
    uint16_t max;
    /** The prime encoded in big-endian bytes. */
    const uint8_t *data;
    /** The length of the prime encoding in bytes. */
    uint16_t len;
} SHARE_PRIME;

/** The data structure for the share operations object. */
struct share_st
{
    /** The methods of an implementation of share operations. */
    SHARE_METH *meth;
    /** The length of the secret in bytes. */
    uint16_t len;
    /** The mask for the top word. */
    uint8_t mask;
    /** The number of parts required to calculate the secret. */
    uint8_t parts;
    /** The length of the prime in bytes. */
    uint16_t prime_len;
    /** The prime as a number object. */
    void *prime;
    /** An array of number objects. */
    void **num;
    /** An array of number objects. */
    void **y;
    /** Storage for encoded and decoded numbers. */
    uint8_t *random;
    /** Result number object. */
    void *res;
    /** Count of splits generated when splitting or added when joining. */
    int cnt;
};

/** The prime that supports up to 128-bit secrets. */
static const uint8_t prime_128[] =
{
    0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe7
};

/** The prime that supports up to 192-bit secrets. */
static const uint8_t prime_192[] =
{
    0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe1
};

/** The prime that supports up to 256-bit secrets. */
static const uint8_t prime_256[] =
{
    0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa3,
};

/** The list of supported primes. */
static SHARE_PRIME share_primes[] =
{
    /* 0x1ffffffffffffffffffffffffffffffe7 */
    { 128, prime_128, sizeof(prime_128) },
    /* 0x1ffffffffffffffffffffffffffffffffffffffffffffffe1 */
    { 192, prime_192, sizeof(prime_192) },
    /* 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa3 */
    { 256, prime_256, sizeof(prime_256) },
};

/** The number of primes supported. */
#define SHARE_PRIME_NUM ((int)(sizeof(share_primes)/(sizeof(*share_primes))))

/**
 * Retrieve the prime that supports the secret length specified.
 *
 * @param [in]  len   The length of the secret in bits.
 * @param [out] data  The encoded prime.
 * @param [out] dlen  The length of the encoded prime in bytes.
 * @param [out] bits  The length of the encoded prime in bits.
 * @return  NOT_FOUND when the length is greater than any supported prime.<br>
 *          NONE otherwise.
 */
SHARE_ERR share_prime_get(uint16_t len, const uint8_t **data, uint16_t *dlen,
    uint16_t *bits)
{
    SHARE_ERR err = NOT_FOUND;
    int i;

    /* Return the first prime that is big enough to support secret. */
    for (i=0; i<SHARE_PRIME_NUM; i++)
    {
        if (len <= share_primes[i].max)
        {
            *data = share_primes[i].data;
            *dlen = share_primes[i].len;
            *bits = share_primes[i].max;
            err = NONE;
            break;
        }
    }

    return err;
}


/**
 * Create a new object that is used to split and join secrets.
 *
 * @param [in]  len    The length of the secret in bytes.
 * @param [in]  parts  The number of parts required to recreate secret.
 * @param [out] share  The new share operation object.
 * @return  PARAM_NULL when share is NULL.
 *          PARAM_BAD_VALUE when parts and/or length are invalid.<br>
 *          NOT_FOUND when no prime or implementation supports the requirements.
 *          <br>
 *          ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_new(uint16_t len, uint8_t parts, SHARE **share)
{
    SHARE_ERR err = NONE;
    SHARE *s = NULL;
    SHARE_METH *meth;
    uint16_t prime_bits;
    uint16_t prime_len;
    const uint8_t *prime_data;
    void *prime = NULL;
    int i;

    if (share == NULL)
    {
        err = PARAM_NULL;
        goto end;
    }

    /* Cannot split a secret into 0 or one splits.
     * Don't allow excessive number of parts.
     * A secret must be at least one byte.
     */
    if ((parts < 2) || (parts > SHARE_PARTS_MAX) || (len == 0))
    {
        err = PARAM_BAD_VALUE;
        goto end;
    }

    /* Retrieve the matching prime. */
    err = share_prime_get(len, &prime_data, &prime_len, &prime_bits);
    if (err != NONE) goto end;

    /* Retrieve an implementation. */
    err = share_meths_get(prime_bits, parts,  &meth);
    if (err != NONE) goto end;

    err = meth->num_new(prime_len, &prime);
    if (err != NONE) goto end;
    err = meth->num_from_bin(prime_data, prime_len, prime);
    if (err != NONE) goto end;

    /* Allocate dynamic memory and initialize for object. */
    s = malloc(sizeof(*s));
    if (s == NULL)
    {
        err = ALLOC;
        goto end;
    }
    memset(s, 0, sizeof(*s));

    /* Initialize object. */
    s->meth = meth;
    s->len = (len + 7) / 8;
    s->mask = ((len & 7) == 0) ? 0xff : (1 << (len & 7)) - 1;
    s->parts = parts;
    s->prime_len = prime_len;
    s->prime = prime;
    prime = NULL;
    s->num = malloc(parts * sizeof(*s->num));
    s->y = malloc(parts * sizeof(*s->y));
    s->random = malloc(prime_len);
    if ((s->num == NULL) || (s->y == NULL) || (s->random == NULL))
    {
        err = ALLOC;
        goto end;
    }
    memset(s->num, 0, parts * sizeof(*s->num));
    memset(s->y, 0, parts * sizeof(*s->num));
    memset(s->random, 0, prime_len - s->len);

    /* Create numbers to support split and join operations. */
    for (i=0; i<s->parts; i++)
    {
        if (s->num[i] == NULL)
        {
            err = s->meth->num_new(s->prime_len, &s->num[i]);
            if (err != NONE) goto end;
        }
    }
    for (i=0; i<s->parts; i++)
    {
        if (s->y[i] == NULL)
        {
            err = s->meth->num_new(s->prime_len, &s->y[i]);
            if (err != NONE) goto end;
        }
    }
    /* Create a number to hold the result of the calculation. */
    err = s->meth->num_new(s->prime_len, &s->res);
    if (err != NONE) goto end;

    *share = s;
    s = NULL;
end:
    if (prime != NULL) meth->num_free(prime);
    SHARE_free(s);
    return err;
}

/**
 * Free the dynamic memory of the object.
 *
 * @param [in] share  The share operation object.
 */
void SHARE_free(SHARE *share)
{
    int i;

    if (share != NULL)
    {
        share->meth->num_free(share->res);
        if (share->random != NULL) free(share->random);
        if (share->y != NULL)
        {
            for (i=0; i<share->parts; i++)
                share->meth->num_free(share->y[i]);
            free(share->y);
        }
        if (share->num != NULL)
        {
            for (i=0; i<share->parts; i++)
                share->meth->num_free(share->num[i]);
            free(share->num);
        }
        share->meth->num_free(share->prime);
        free(share);
    }
}

/**
 * Get the length of the encoded share.
 *
 * @param [in]  share  The share operation object.
 * @param [out] len    The length of the encoded share in bytes.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_get_len(SHARE *share, uint16_t *len)
{
    SHARE_ERR err = NONE;

    if ((share == NULL) || (len == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }

    *len = share->prime_len * 2;
end:
    return err;
}

/**
 * Get the number of splits generated or added for joining.
 *
 * @param [in]  share  The share operation object.
 * @param [out] num    The number of splits.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_get_num(SHARE *share, uint16_t *num)
{
    SHARE_ERR err = NONE;

    if ((share == NULL) || (num == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }

    *num = share->cnt;
end:
    return err;
}

/**
 * Get the name of the implementation method.
 *
 * @param [in]  share  The share operation object.
 * @param [out] name   The name of the implementation method.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_get_impl_name(SHARE *share, char **name)
{
    SHARE_ERR err = NONE;

    if ((share == NULL) || (name == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }

    *name = share->meth->name;
end:
    return err;
}

/**
 * Initialize the generation of splits from the secret.
 *
 * @param [in] share   The share operation object.
 * @param [in] secret  The data of the secret to split in big-endian bytes.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM when the random number generator fails.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_split_init(SHARE *share, uint8_t *secret)
{
    SHARE_ERR err = NONE;
    int i;
    uint8_t *r, *t = NULL;

    if ((share == NULL) || (secret == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }

    /* Generate all the random coefficient data at once - quicker. */
    t = malloc(share->len * (share->parts-1));
    if (t == NULL)
    {
        err = ALLOC;
        goto end;
    }
    if (SHARE_random(t, share->len * (share->parts-1)) != 0)
    {
        err = RANDOM;
        goto end;
    }

    /* The first coefficient is the secret. */
    r = &share->random[share->prime_len-share->len];
    memset(share->random, 0, share->prime_len-share->len);
    memcpy(r, secret, share->len);
    err = share->meth->num_from_bin(share->random, share->prime_len,
        share->num[0]);
    if (err != NONE) goto end;

    /* Create number objects with the data for the random coefficients. */
    for (i=1; i<share->parts; i++)
    {
        memcpy(r, &t[share->len * (i-1)], share->len);
        r[0] &= share->mask;
        err = share->meth->num_from_bin(share->random, share->prime_len,
            share->num[i]);
        if (err != NONE) goto end;
    }

    /* Initialize the count of generated splits. */
    share->cnt = 0;
end:
    if (t != NULL) free(t);
    return err;
}

/**
 * Generate a split for the secret.
 * A random x is generated. There is a small chance that an x will be repeated.
 *
 * @param [in] share  The share operation object.
 * @param [in] data   The data of the generated split as big-endian bytes.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM when the random number generator fails.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_split(SHARE *share, uint8_t *data)
{
    SHARE_ERR err = NONE;
    void *x;
    uint8_t *r;

    if ((share == NULL) || (data == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }

    x = share->y[0];
    r = &share->random[share->prime_len-share->len];

    /* Generate a random x. */
    if (SHARE_random(r, share->len) != 0)
    {
        err = RANDOM;
        goto end;
    }
    r[0] &= share->mask;
    err = share->meth->num_from_bin(share->random, share->prime_len, x);
    if (err != NONE) goto end;

    /* Calculate the corresponding y using the coefficients. */
    err = share->meth->split(share->prime, share->parts, share->num, x,
        share->res);
    if (err != NONE) goto end;

    /* Encode the x and y ordinates. */
    err = share->meth->num_to_bin(x, data, share->prime_len);
    if (err != NONE) goto end;
    data += share->prime_len;
    err = share->meth->num_to_bin(share->res, data, share->prime_len);
    if (err != NONE) goto end;

    share->cnt++;
end:
    return err;
}

/**
 * Initialize the joining of splits to calculate the secret.
 *
 * @param [in] share   The share operation object.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_join_init(SHARE *share)
{
    SHARE_ERR err = NONE;

    if (share == NULL)
    {
        err = PARAM_NULL;
        goto end;
    }

    /* Initialize the number of splits stored. */
    share->cnt = 0;
end:
    return err;
}

/**
 * Add a split to be joined.
 * Ignore any splits added beyond the minimum number required.
 *
 * @param [in] share  The share operation object.
 * @param [in] data   The data of the generated split as big-endian bytes.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          ALLOC when dynamic memory allocation fails.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_join_update(SHARE *share, uint8_t *data)
{
    SHARE_ERR err = NONE;

    if ((share == NULL) || (data == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }
    if (share->parts == share->cnt)
        goto end;

    /* Split is an x and a y ordinate. */
    /* X */
    err = share->meth->num_from_bin(data, share->prime_len,
        share->num[share->cnt]);
    if (err != NONE) goto end;
    data += share->prime_len;
    /* Y */
    err = share->meth->num_from_bin(data, share->prime_len,
        share->y[share->cnt]);
    if (err != NONE) goto end;

    share->cnt++;
end:
    return err;
}

/**
 * Calculate the secret from the splits.
 *
 * @param [in] share   The share operation object.
 * @param [in] secret  The data of the secret as big-endian bytes.
 * @return  PARAM_NULL when a parameter is NULL.<br>
 *          ALLOC when dynamic memory allocation fails.<br>
 *          INVALID_DATA when the number of splits added is less than the number
 *          required (parts).<br>
 *          FAILED when the secret calculated is larger than expected.<br>
 *          NONE otherwise.
 */
SHARE_ERR SHARE_join_final(SHARE *share, uint8_t *secret)
{
    SHARE_ERR err = NONE;
    int16_t o;
    int i;

    if ((share == NULL) || (secret == NULL))
    {
        err = PARAM_NULL;
        goto end;
    }
    /* Must have parts number of splits to be able to calcuate secret. */
    if (share->cnt < share->parts)
    {
        err = INVALID_DATA;
        goto end;
    }

    err = share->meth->join(share->prime, share->parts, share->num, share->y,
        share->res);
    if (err != NONE) goto end;

    /* Encode the number up to prime length bytes. */
    err = share->meth->num_to_bin(share->res, share->random, share->prime_len);
    if (err != NONE) goto end;

    /* Offset to the start of the secret. */
    o = share->prime_len-share->len;
    /* Check that the calculated secret isn't too large. */
    for (i=0; i<o; i++)
    {
        if (share->random[i] != 0)
        {
            err = FAILED;
            goto end;
        }
    }

    memcpy(secret, &share->random[o], share->len);
end:
    return err;
}

