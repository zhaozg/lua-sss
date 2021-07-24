#include "sss/randombytes.c"
#include "sss/sss.c"
#include "sss/hazmat.c"
#include "sss/tweetnacl.c"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

static int create_shares(lua_State *L)
{
	size_t sz;
	sss_Share *shares = NULL;
	uint8_t n, k;

	const char* msg = luaL_checklstring(L, 1, &sz);
	luaL_argcheck(L, sz==sss_MLEN, 1, "invalid length");

	n = (uint8_t)luaL_checkint(L, 2);
	k = (uint8_t)luaL_checkint(L, 3);
	luaL_argcheck(L, n>=k && k>=1, 3, "out of range");

	shares = malloc(sizeof(sss_Share)*n);

	sss_create_shares(shares, (const uint8_t*)msg, n, k);

	lua_newtable(L);
	for (k=0; k<n; k++)
	{
		lua_pushlstring(L, (const char*)shares[k], sss_SHARE_LEN);
		lua_rawseti(L, -2, k+1);
	}
	free(shares);
	return 1;
}

static int combine_shares(lua_State *L)
{
	uint8_t n, i;
	int ret;
	size_t sz;
	sss_Share *shares = NULL;
	const char *dat;
	uint8_t restored[sss_MLEN] = {0};

	luaL_checktype(L, 1, LUA_TTABLE);
	n = lua_objlen(L, 1);
	luaL_argcheck(L, n > 0, 1, "empty");

	shares = malloc(sizeof(sss_Share)*n);
	for(i=0; i<n; i++)
	{
		lua_rawgeti(L, 1, i + 1);
		dat = luaL_checklstring(L, -1, &sz);
		if (sz!=sss_SHARE_LEN)
		{
			free(shares);
			luaL_argerror(L, 1, "items invalid length");
		}
		lua_pop(L, 1);
		memcpy(shares[i], dat, sz);
	}

	// Combine some of the shares to restore the original secret
	ret = sss_combine_shares(restored, shares, n);
	free(shares);
	if (ret==0)
	{
		lua_pushlstring(L, (const char*)restored, sss_MLEN);
	}else
		lua_pushnil(L);
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

	lua_pushliteral(L, "MLEN");
	lua_pushinteger(L, sss_MLEN);
	lua_rawset(L, -3);

  return 1;
}
