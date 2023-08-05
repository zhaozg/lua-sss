#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#if LUA_VERSION_NUM > 501
#define lua_objlen lua_rawlen
#endif

#if !defined(USE_OPENSSL)

#define IRREDUCTIBLE_POLY 0x011b

static uint8_t **MULTIPLICATIVE_INVERSE_TABLE = NULL;

// Add two polynomials in GF(2 ^ 8)
inline static uint8_t p_add(uint8_t a, uint8_t b) { return a ^ b; }

// Multiply a polynomial by x in GF(2 ^ 8)
inline static uint8_t time_x(uint8_t a) {
  if ((a >> 7) & 0x1) {
    return (a << 1) ^ IRREDUCTIBLE_POLY;
  } else {
    return (a << 1);
  }
}

inline static uint8_t time_x_power(uint8_t a, uint8_t x_power) {
  uint8_t res = a;
  for (; x_power > 0; x_power--) {
    res = time_x(res);
  }
  return res;
}

// Multiply two polynomials in GF(2 ^ 8)
inline static uint8_t p_mul(uint8_t a, uint8_t b) {
  uint8_t res = 0;
  for (int degree = 7; degree >= 0; degree--) {
    if ((b >> degree) & 0x1) {
      res = p_add(res, time_x_power(a, degree));
    }
  }
  return res;
}

inline static uint8_t p_inv(uint8_t a) {

  // Build the table so that table[a][1] = inv(a)
  if (MULTIPLICATIVE_INVERSE_TABLE == NULL) {
    MULTIPLICATIVE_INVERSE_TABLE = (uint8_t **)malloc(256 * sizeof(uint8_t *));
    for (int row = 0; row < 256; row++) {
      MULTIPLICATIVE_INVERSE_TABLE[row] =
          (uint8_t *)malloc(256 * sizeof(uint8_t));

      for (int col = 0; col < 256; col++) {
        MULTIPLICATIVE_INVERSE_TABLE[row][p_mul(row, col)] = col;
      }
    }
  }
  return MULTIPLICATIVE_INVERSE_TABLE[a][1];
}

// Divide two polynomials in GF(2 ^ 8)
inline static uint8_t p_div(uint8_t a, uint8_t b) { return p_mul(a, p_inv(b)); }

inline static uint8_t rand_byte() { return rand() % 0xff; }

inline static uint8_t *make_random_poly(int degree, uint8_t secret) {
  uint8_t *poly = malloc((degree + 1) * sizeof(uint8_t));
  for (; degree > 0; degree--) {
    poly[degree] = rand_byte();
  }
  poly[0] = secret;
  return poly;
}

inline static uint8_t poly_eval(uint8_t *poly, int degree, uint8_t x) {
  uint8_t res = 0;
  for (; degree >= 0; degree--) {
    uint8_t coeff = poly[degree];
    uint8_t term = 0x01;
    for (int times = degree; times > 0; times--) {
      term = p_mul(term, x);
    }
    res = p_add(res, p_mul(coeff, term));
  }
  return res;
}

// Interpolate a(k - 1) degree polynomial and evaluate it at x = 0
inline static uint8_t poly_interpolate(uint8_t *xs, uint8_t *ys, int k) {
  uint8_t res = 0;

  for (int j = 0; j < k; j++) {
    uint8_t prod = 0x01;
    for (int m = 0; m < k; m++) {
      if (m != j) {
        prod = p_mul(prod, p_div(xs[m], p_add(xs[m], xs[j])));
      }
    }
    res = p_add(res, p_mul(ys[j], prod));
  }
  return res;
}

inline static uint8_t **split(uint8_t *secret, int secret_size, int n, int k) {
  // n rows x(secret_size + 1) cols matrix
  uint8_t **shares = malloc(n * sizeof(uint8_t *));
  for (int i = 0; i < n; i++) {
    shares[i] = malloc((secret_size + 1) * sizeof(uint8_t));

    // x
    shares[i][0] = rand_byte();
  }

  for (int secret_idx = 0; secret_idx < secret_size; secret_idx++) {
    uint8_t *poly = make_random_poly(k - 1, secret[secret_idx]);

    // Evaluate poly on every one of the n x points
    for (int i = 0; i < n; i++) {
      shares[i][secret_idx + 1] = poly_eval(poly, k - 1, shares[i][0]);
    }
  }

  return shares;
}

inline static uint8_t *join(uint8_t **shares, int secret_size, int k) {
  uint8_t *secret = malloc(secret_size * sizeof(uint8_t));

  for (int secret_idx = 1; secret_idx <= secret_size; secret_idx++) {
    uint8_t *xs = (uint8_t *)malloc(k * sizeof(uint8_t));
    uint8_t *ys = (uint8_t *)malloc(k * sizeof(uint8_t));
    for (int i = 0; i < k; i++) {
      xs[i] = shares[i][0];
      ys[i] = shares[i][secret_idx];

      secret[secret_idx - 1] = poly_interpolate(xs, ys, k);
    }
  }

  return secret;
}
#else

#include <openssl/bn.h>

#include "share.c"
#include "share_openssl.c"

#endif

static int create_shares(lua_State *L) {
  size_t sz;
  uint8_t n, k;

  const char *secret = luaL_checklstring(L, 1, &sz);

  n = (uint8_t)luaL_checkinteger(L, 2);
  k = (uint8_t)luaL_checkinteger(L, 3);

  luaL_argcheck(L, n >= k && k > 1, 3, "out of range");

#if !defined(USE_OPENSSL)
  uint8_t **shares = split((uint8_t *)secret, sz, n, k);
  if (shares != NULL) {
    lua_newtable(L);
    for (k = 0; k < n; k++) {
      lua_pushlstring(L, (const char *)shares[k], sz + 1);
      lua_rawseti(L, -2, k + 1);
      free(shares[k]);
    }
    free(shares);
    return 1;
  }
#else
  SHARE_ERR err;
  SHARE *share = NULL;
  uint8_t **split = NULL;

  err = SHARE_new(sz * 8, k, &share);
  if (err == NONE) {
    uint16_t len;

    /* Get the length of the encoded data. */
    err = SHARE_get_len(share, &len);
    if (err != NONE)
      goto end;

    split = malloc(n * sizeof(*split));
    if (split == NULL)
      goto end;

    memset(split, 0, n * sizeof(*split));
    for (k = 0; k < n; k++) {
      split[k] = malloc(len);
      if (split[k] == NULL)
        goto end;
    }

    /* Split */
    err = SHARE_split_init(share, (uint8_t*)secret);
    if (err != NONE)
      goto end;

    for (k = 0; err == NONE && k < n; k++)
      err = SHARE_split(share, split[k]);
    if (err != NONE)
      goto end;

    lua_newtable(L);
    for (k = 0; k < n; k++) {
      lua_pushlstring(L, (const char *)split[k], len);
      lua_rawseti(L, -2, k + 1);
      free(split[k]);
    }
end:
    free(split);
    SHARE_free(share);
    return err == NONE ? 1 : 0;
  }
#endif
  return 0;
}

static int combine_shares(lua_State *L) {
  uint8_t n, i;
  int size = 0;
  uint8_t *restored;
  uint8_t **shares;

  luaL_checktype(L, 1, LUA_TTABLE);
  n = lua_objlen(L, 1);
  luaL_argcheck(L, n > 0, 1, "empty table");

#if !defined(USE_OPENSSL)
  shares = (uint8_t **)malloc(n * sizeof(void *));
  for (i = 0; i < n; i++) {
    size_t sz;
    lua_rawgeti(L, 1, i + 1);
    shares[i] = (uint8_t *)luaL_checklstring(L, -1, &sz);
    lua_pop(L, 1);
    if (i == 0)
      size = sz;
    else
      luaL_argcheck(L, size == sz, 1, "partial secret length mismatch");
  }
  restored = join(shares, size, n);
  if (restored != NULL)
    lua_pushlstring(L, (const char *)restored, size - 1);
  else
    lua_pushnil(L);

  free(shares);
  free(restored);
  n = 1;
#else
  SHARE_ERR err;
  SHARE *share = NULL;
  int len = 0;

  shares = (uint8_t **)malloc(n * sizeof(void *));
  for (i = 0; i < n; i++) {
    size_t sz;
    lua_rawgeti(L, 1, i + 1);
    shares[i] = (uint8_t *)luaL_checklstring(L, -1, &sz);
    lua_pop(L, 1);
    if (i == 0)
      size = sz;
    else
      luaL_argcheck(L, size == sz, 1, "partial secret length mismatch");
  }
  len = (size - 2) / 2;

  err = SHARE_new(len * 8, n, &share);
  if (err == NONE) {
    err = SHARE_join_init(share);
    if (err != NONE)
      goto end;

    for (i = 0; err == NONE && i < n; i++) {
      err = SHARE_join_update(share, shares[i]);
    }

    if (err == NONE) {
      restored = malloc(size);
      err = SHARE_join_final(share, restored);
      if (err == NONE)
      {
        lua_pushlstring(L, (const char *)restored, len);
        n = 1;
      }
      free(restored);
    }
  }
  else
    n = 0;
end:
  free(shares);
  SHARE_free(share);
#endif
  return n;
}

static int generate_random(lua_State *L) {
  int n = luaL_checkinteger(L, 1);
  uint8_t *buf = (uint8_t *)malloc(n);

#if !defined(USE_OPENSSL)
  int i;
  for (i = 0; i < n; i++) {
    buf[i] = rand_byte();
  }
#else
  SHARE_random(buf, n);
#endif

  lua_pushlstring(L, (const char *)buf, n);
  free(buf);
  return 1;
}

LUALIB_API int luaopen_sss(lua_State *L) {
#if !defined(USE_OPENSSL)
  srand(time(NULL));
#endif

  lua_newtable(L);

  lua_pushliteral(L, "create");
  lua_pushcfunction(L, create_shares);
  lua_rawset(L, -3);

  lua_pushliteral(L, "combine");
  lua_pushcfunction(L, combine_shares);
  lua_rawset(L, -3);

  lua_pushliteral(L, "random");
  lua_pushcfunction(L, generate_random);
  lua_rawset(L, -3);

  return 1;
}
