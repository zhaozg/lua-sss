local sss = require'sss'

local function hex2bin(hexstr)
  local unpack = unpack or table.unpack
  local t = {}
  for i = 1, string.len(hexstr) - 1, 2 do
    local doublebytestr = string.sub(hexstr, i, i+1);
    local n = tonumber(doublebytestr, 16);
    t[#t+1] = n
  end
  return string.char(unpack(t))
end

local function bin2hex(binstr)
  local t = {}
  for i = 1, string.len(binstr) do
      local charcode = tonumber(string.byte(binstr, i, i));
      local hex = string.format("%02X", charcode);
      t[#t+1] = hex
  end
  return table.concat(t)
end

local msg = sss.random(32)
assert(#msg==32)
print(bin2hex(msg))

local t = assert(sss.create(msg, 5, 3))
for i=1, #t do
  print(bin2hex(t[i]))
end
table.remove(t)
table.remove(t)

local rec = assert(sss.combine(t));

print(bin2hex(rec))
rec = hex2bin(bin2hex(rec))
assert(rec==msg)
