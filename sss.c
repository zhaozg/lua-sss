#include "sss/randombytes.c"
#include "sss/sss.c"
#include "sss/hazmat.c"
#include "sss/tweetnacl.c"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#if LUA_VERSION_NUM > 501
#define lua_objlen lua_rawlen
#endif

static int create_shares(lua_State *L)
{
	size_t sz;
	sss_Share *shares = NULL;
	uint8_t n, k;

	const char* msg = luaL_checklstring(L, 1, &sz);
	luaL_argcheck(L, sz%8==0, 1, "invalid length");
	luaL_argcheck(L, sz < (255 - sss_KEYSHARE_LEN) , 1, "length too long");

	n = (uint8_t)luaL_checkinteger(L, 2);
	k = (uint8_t)luaL_checkinteger(L, 3);
	luaL_argcheck(L, n>=k && k>=1, 3, "out of range");

	shares = sss_new_shares(sz, n);

	sss_create_shares(shares, (const uint8_t*)msg, sz,  n, k);

	lua_newtable(L);
	for (k=0; k<n; k++)
	{
		lua_pushlstring(L, (const char*)shares[k].share, shares[0].size);
		lua_rawseti(L, -2, k+1);
	}
	sss_free_shares(shares, n);
	return 1;
}

static int combine_shares(lua_State *L)
{
	uint8_t n, i;
	int ret;
	sss_Share *shares = NULL;
	uint8_t *restored;

	luaL_checktype(L, 1, LUA_TTABLE);
	n = lua_objlen(L, 1);
	luaL_argcheck(L, n > 0, 1, "empty");

	shares = sss_new_shares(0, n);
	for(i=0; i<n; i++)
	{
		lua_rawgeti(L, 1, i + 1);
		shares[i].share = (uint8_t*)luaL_checklstring(L, -1, &shares[i].size);
		lua_pop(L, 1);
	}
	if (n>1)
	{
		for(i=1; i<n; i++)
		{
			if(shares[i-1].size != shares[i].size)
				luaL_argerror(L, 1, "items invalid length");
		}
	}

	i = sss_SLEN_TO_MLEN(shares[0].size);
	if (i==0)
	{
		return 0;
	}

	restored = malloc(i);
	memset(restored, 0, i);

	// Combine some of the shares to restore the original secret
	ret = sss_combine_shares(restored, shares, n);
	sss_free_shares(shares, 0);
	if (ret==0)
	{
		lua_pushlstring(L, (const char*)restored, i);
	}else
		lua_pushnil(L);
	free(restored);
	return 1;
}

static int generate_random(lua_State *L)
{
	int n = luaL_checkinteger(L, 1);
	void *buf = malloc(n);

	if (randombytes(buf, n) == 0)
		lua_pushlstring(L, buf, n);
	else
		lua_pushnil(L);

	free(buf);
	return 1;
}

LUALIB_API int
luaopen_sss (lua_State *L)
{
  lua_newtable (L);

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
