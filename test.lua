local sss = require'sss'

local function bin2hex(binstr)
  local t = {}
  for i = 1, string.len(binstr) do
      local charcode = tonumber(string.byte(binstr, i, i));
      local hex = string.format("%02X", charcode);
      t[#t+1] = hex
  end
  return table.concat(t)
end

local msg = sss.random(256)
print('msg', bin2hex(msg))

local t = assert(sss.create(msg, 5, 3))
for i=1, #t do
  print('part', bin2hex(t[i]))
end
table.remove(t)
table.remove(t)
local rec = assert(sss.combine(t));

print('rec', bin2hex(rec))
assert(rec==msg)
