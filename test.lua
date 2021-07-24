local sss = require'sss'
local openssl = require'openssl'

local msg = openssl.random(32)
print(openssl.hex(msg))

local t = assert(sss.create(msg, 5, 3))
for i=1, #t do
  print(openssl.hex(t[i]))
end
table.remove(t)
table.remove(t)

local rec = assert(sss.combine(t));

print(openssl.hex(rec))
assert(rec==msg)
