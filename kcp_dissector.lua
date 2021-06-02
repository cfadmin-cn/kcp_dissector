---@ KCP Protocol dissector plugin
---@ Author CandyMi https://github.com/CandyMi  Written on June 2, 2021

do

  local bit32 = bit32 or bit

  local NAME = "KCP"
  local PORT = 8082

  local KCP = Proto(NAME, "KCP Protocol")

  -- KCP Protocol Fields.
  local conv  = ProtoField.uint32(NAME .. ".conv", "Conv", base.DEC)
  local cmd   = ProtoField.uint8(NAME .. ".cmd", "Cmd", base.DEC)
  local frg   = ProtoField.uint8(NAME .. ".frg", "Frg", base.DEC)
  local wnd   = ProtoField.uint16(NAME .. ".wnd", "Wnd", base.DEC)

  local ts    = ProtoField.uint32(NAME .. ".ts", "ts", base.DEC)
  local sn    = ProtoField.uint32(NAME .. ".sn", "sn", base.DEC)
  local una   = ProtoField.uint32(NAME .. ".una", "una", base.DEC)
  local len   = ProtoField.uint32(NAME .. ".len", "len", base.DEC)
  local data  = ProtoField.string(NAME .. ".data", "data", base.UNICODE)

--[[

  0               4   5   6       8 (BYTE)
  +---------------+---+---+-------+
  |     conv      |cmd|frg|  wnd  |
  +---------------+---+---+-------+   8
  |     ts        |     sn        |
  +---------------+---------------+  16
  |     una       |     len       |
  +---------------+---------------+  24
  |                               |
  |        DATA (optional)        |
  |                               |
  +-------------------------------+

--]]

  KCP.fields = {
    conv, cmd, frg, wnd,
    ts,        sn,
    una,       len,
           data
  }

  local function CMD_TO_STRING(CMD)
    if CMD:le_uint() == 81 then
      return "CMD_PUSH(81)"
    elseif CMD:le_uint() == 82 then
      return "CMD_ACK(82)"
    elseif CMD:le_uint() == 83 then
      return "CMD_WASK(83)"
    elseif CMD:le_uint() == 84 then
      return "CMD_WINS(84)"
    end
    return CMD:le_uint()
  end

  local function WND_TO_STRING(WND)
    return "WND_RCV_SIZE(" .. WND:le_uint() .. ")"
  end

  local function FRG_TO_STRING(FRG)
    return FRG:uint() == 1 and "YES(1)" or "FALSE(0)"
  end


  local function LEN_TO_STRING(LEN)
    return LEN:le_uint()
  end

  local segment = 0

  -- KCP dissect packet
  function KCP.dissector (Buffer, Menu, T)

    -- Creating a protocol tree.
    local Tree = T:add(KCP, Buffer())

    -- Registered Protocol Name
    Menu.cols.protocol = KCP.name

    -- Calculate the data offset value
    local offset  = 0


    local CONV =  Buffer(offset, 4)
    Tree:add_le(conv, CONV)
    Tree:append_text(", conv: " .. CONV:le_uint())
    offset = offset + 4

    local CMD =  Buffer(offset, 1)
    Tree:add_le(cmd, CMD)
    Tree:append_text(", cmd: " .. CMD_TO_STRING(CMD))
    offset = offset + 1

    local FRG =  Buffer(offset, 1)
    Tree:add_le(frg, FRG)
    Tree:append_text(", frg: " .. FRG_TO_STRING(FRG))
    offset = offset + 1

    local WND =  Buffer(offset, 2)
    Tree:add_le(wnd, WND)
    Tree:append_text(", wnd: " .. WND_TO_STRING(WND))
    offset = offset + 2

    local TS =  Buffer(offset, 4)
    Tree:add_le(ts, TS)
    Tree:append_text(", ts: " .. TS:le_uint())
    offset = offset + 4

    local SN =  Buffer(offset, 4)
    Tree:add_le(sn, SN)
    Tree:append_text(", sn: " .. SN:le_uint())
    offset = offset + 4

    local UNA =  Buffer(offset, 4)
    Tree:add_le(una, UNA)
    Tree:append_text(", una: " .. UNA:le_uint())
    offset = offset + 4

    local LEN =  Buffer(offset, 4)
    Tree:add_le(len, LEN)
    Tree:append_text(", len: " .. LEN_TO_STRING(LEN))
    offset = offset + 4

    local DATA =  Buffer(offset, Buffer:len() - offset)
    Tree:add(data, DATA:string(ENC_UTF_8))
    -- Tree:append_text(", data: " .. DATA:string(ENC_UTF_8))
    offset = offset + (Buffer:len() - offset)

    if CMD:le_uint() == 81 then
      local info = "CMD_PUSH, SN(" .. SN:le_uint() .. ")"
      if UNA:le_uint() > 0 then
        info = info .. "WAIT_SN(" .. UNA:le_uint() .. ")"
      end
      Menu.cols.info = info
    elseif CMD:le_uint() == 82 then
      Menu.cols.info = "CMD_ACK, SN(" .. SN:le_uint() .. "), NEXT_SN(" .. UNA:le_uint() .. ")"
    elseif CMD:le_uint() == 83 then
      -- TODO
    elseif CMD:le_uint() == 84 then
      -- TODO
    end

  end

  DissectorTable.get("udp.port"):add(PORT, KCP)
end
