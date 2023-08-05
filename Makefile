T=sss

PREFIX		?=/usr/local
PKG_CONFIG	?=pkg-config
CC		:= $(CROSS)$(CC)
AR		:= $(CROSS)$(AR)
LD		:= $(CROSS)$(LD)
LUA		:=

#OS auto detect
ifneq (,$(TARGET_SYS))
  SYS		:= $(TARGET_SYS)
else
  SYS		:= $(shell gcc -dumpmachine)
endif

#Lua auto detect
LUA_VERSION	:= $(shell $(PKG_CONFIG) luajit --print-provides)
ifeq ($(LUA_VERSION),)
  # Not found luajit package, try lua
  LUA_VERSION	:= $(shell $(PKG_CONFIG) lua --print-provides)
  ifeq ($(LUA_VERSION),)
    # Not found lua package, try from prefix
    LUA_VERSION := $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= -I$(PREFIX)/include
    LUA_LIBS	?= -L$(PREFIX)/lib #-llua
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  else
    # Found lua package
    LUA_VERSION	:= $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= $(shell $(PKG_CONFIG) lua --cflags)
    LUA_LIBS	?= $(shell $(PKG_CONFIG) lua --libs)
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  endif
else
  # Found luajit package
  LUA_VERSION	:= $(shell luajit -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
  LUA_CFLAGS	?= $(shell $(PKG_CONFIG) luajit --cflags)
  LUA_LIBS	?= $(shell $(PKG_CONFIG) luajit --libs)
  LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
  LUA		:= luajit
endif

ifneq (, $(findstring linux, $(SYS)))
  # Do linux things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC # -Wl,--no-undefined
endif

ifneq (, $(findstring apple, $(SYS)))
  # Do darwin things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -undefined dynamic_lookup -ldl
  MACOSX_DEPLOYMENT_TARGET="11.0"
  CC		:= MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET} $(CC)
endif

ifneq (, $(findstring mingw, $(SYS)))
  # Do mingw things
  CFLAGS	+= -DLUA_LIB -DLUA_BUILD_AS_DLL -DWIN32_LEAN_AND_MEAN
endif

ifneq (, $(findstring cygwin, $(SYS)))
  # Do cygwin things
  CFLAGS	+= -fPIC
endif

ifneq (, $(findstring iOS, $(SYS)))
  # Do iOS things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -ldl
endif

#custom config

ifeq (.config, $(wildcard .config))
  include .config
endif

LIBNAME= $T.so.$V

CFLAGS		+= $(LUA_CFLAGS) $(TARGET_FLAGS)
# Compilation directives
WARN_MIN	 = -Wall -Wno-unused-value -Wno-unused-function
WARN		 = -Wall
WARN_MOST	 = $(WARN) -W -Waggregate-return -Wcast-align -Wmissing-prototypes     \
		   -Wnested-externs -Wshadow -Wwrite-strings -pedantic
CFLAGS		+= -g $(WARN_MIN) -DPTHREADS

OBJS += sss.o

.PHONY: all install test info doc

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $?

all: $T.so
	@echo "Target system: "$(SYS)

$T.so: lib$T.a
	$(CC) -shared -o $@ $T.o -L. -l$T $(LDFLAGS)

lib$T.a: $(OBJS)
	$(AR) rcs $@ $?

install: all
	mkdir -p $(LUA_LIBDIR)
	echo cp $T.so $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)
doc:
	ldoc src -d doc

info:
	@echo "Target system: "$(SYS)
	@echo "CC:" $(CC)
	@echo "AR:" $(AR)
	@echo "PREFIX:" $(PREFIX)

test:	all
	cd test && LUA_CPATH=../?.so $(LUA) test.lua && cd ..

clean:
	rm -f $T.so lib$T.a *.o $(OBJS)

# vim: ts=8 sw=8 noet
