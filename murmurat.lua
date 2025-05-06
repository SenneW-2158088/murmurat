-- murmurat.lua - Wireshark dissector for MURMURAT protocol

-- Create a new protocol
murmurat_proto = Proto("murmurat", "MURMURAT Protocol")

-- Define fields for the protocol
local f_type = ProtoField.uint8("murmurat.type", "Message Type", base.DEC,
    {[0] = "DH", [1] = "HELLO", [2] = "DATA"})
local f_length = ProtoField.uint16("murmurat.length", "Length", base.DEC)
local f_nonce = ProtoField.uint8("murmurat.nonce", "Nonce", base.HEX)
local f_timestamp = ProtoField.uint32("murmurat.timestamp", "Timestamp", base.DEC)
local f_pubkey_id = ProtoField.uint32("murmurat.pubkey_id", "Public Key ID", base.HEX)
local f_data = ProtoField.bytes("murmurat.data", "Encrypted Data")
local f_signature = ProtoField.bytes("murmurat.signature", "Signature")
local f_dh_public = ProtoField.bytes("murmurat.dh_public", "DH Public Value")
local f_rsa_public = ProtoField.bytes("murmurat.rsa_public", "RSA Public Value")
local f_holiday = ProtoField.bool("murmurat.holiday", "Is Holiday Message")

-- Register all fields
murmurat_proto.fields = {f_type, f_length, f_nonce, f_timestamp, f_pubkey_id,
                         f_data, f_signature, f_dh_public, f_rsa_public, f_holiday}

-- Dissector function
function murmurat_proto.dissector(buffer, pinfo, tree)
    -- Early return if the buffer is too short
    if buffer:len() < 1 then return end

    -- Set the protocol name in the packet info column
    pinfo.cols.protocol = "MURMURAT"

    -- Create a subtree for our protocol
    local subtree = tree:add(murmurat_proto, buffer())

    -- Read message type (first byte)
    local msg_type = buffer(0,1):uint()
    subtree:add(f_type, buffer(0,1))

    -- Parse based on message type
    if msg_type == 0 then  -- DH Message
        subtree:append_text(": DH Message")
        pinfo.cols.info = "DH Message"
        if buffer:len() >= 256 then
            subtree:add(f_dh_public, buffer(1, 255))
        end

    elseif msg_type == 1 then  -- HELLO Message
        subtree:append_text(": HELLO Message")
        pinfo.cols.info = "HELLO Message"
        if buffer:len() >= 5 then
            subtree:add(f_pubkey_id, buffer(1, 4))
            if buffer:len() >= 516 then
                subtree:add(f_rsa_public, buffer(5, 511))
            end
        end

    elseif msg_type == 2 then  -- DATA Message
        subtree:append_text(": DATA Message")
        pinfo.cols.info = "DATA Message"

        if buffer:len() >= 3 then
            local length = buffer(1, 2):uint()
            subtree:add(f_length, buffer(1, 2))

            if buffer:len() >= 4 then
                subtree:add(f_nonce, buffer(3, 1))

                if buffer:len() >= 8 then
                    local timestamp = buffer(4, 4):uint()
                    local timestamp_field = subtree:add(f_timestamp, buffer(4, 4))

                    -- Convert Unix timestamp to human-readable time
                    local time_str = os.date("!%Y-%m-%d %H:%M:%S", timestamp)
                    timestamp_field:append_text(" (" .. time_str .. ")")

                    -- Check if this is February 14th
                    local month_day = os.date("!%m-%d", timestamp)
                    if month_day == "02-14" then
                        subtree:add(f_holiday, 1):append_text(" (February 14th - Holiday Message)")
                    else
                        subtree:add(f_holiday, 0)
                    end

                    -- Data field starts at offset 8
                    local data_size = length - 7  -- Length includes all fields after length
                    if buffer:len() >= 8 + data_size then
                        subtree:add(f_data, buffer(8, data_size))

                        -- Public key ID after data
                        local pubkey_offset = 8 + data_size
                        if buffer:len() >= pubkey_offset + 4 then
                            subtree:add(f_pubkey_id, buffer(pubkey_offset, 4))

                            -- Signature (last 512 bytes)
                            local sig_offset = pubkey_offset + 4
                            if buffer:len() >= sig_offset + 512 then
                                subtree:add(f_signature, buffer(sig_offset, 512))
                            end
                        end
                    end
                end
            end
        end
    end
end

-- Load the UDP port table
local udp_table = DissectorTable.get("udp.port")
-- Register our dissector for UDP port 1400
udp_table:add(1400, murmurat_proto)
