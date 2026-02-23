-- Iridium Satellite Data Dissector for Wireshark
-- Enhanced Version: Supports deep payload analysis, device tracking, and advanced field extraction
-- Author: Original by You, Enhanced by Claude
-- Dissects Iridium data encapsulated in UDP packets (port 15007)

local iridium_proto = Proto("IridiumUDP", "Iridium Satellite Data over UDP")

-- 1. DEFINE ALL PROTOCOL FIELDS (Organized by category)
local fields = {
    -- Core Metadata Fields
    frame_type    = ProtoField.string("iridium.frame_type", "Frame Type"),
    packet_id     = ProtoField.string("iridium.packet_id", "Packet ID"),
    timestamp     = ProtoField.string("iridium.timestamp", "Timestamp (ms)"),
    frequency     = ProtoField.uint32("iridium.frequency", "Frequency (Hz)", base.DEC),
    confidence    = ProtoField.uint8("iridium.confidence", "Confidence (%)", base.DEC),
    signal_dbfs   = ProtoField.float("iridium.signal_dbfs", "Signal (dBFS)"),
    noise_dbfs    = ProtoField.float("iridium.noise_dbfs", "Noise (dBFS)"),
    snr_db        = ProtoField.float("iridium.snr_db", "SNR (dB)"),
    length        = ProtoField.uint16("iridium.length", "Length", base.DEC),
    direction     = ProtoField.string("iridium.direction", "Direction"),
    frame_status  = ProtoField.string("iridium.frame_status", "Frame Status"),
    
    -- Raw Data Fields
    binary_data   = ProtoField.string("iridium.binary_data", "Binary Data"),
    extra_bits    = ProtoField.string("iridium.extra_bits", "Extra Bits"),
    hex_payload   = ProtoField.bytes("iridium.hex_payload", "Hex Payload", base.SPACE),
    raw_data      = ProtoField.string("iridium.raw_data", "Raw Data"),
    
    -- Message Type Fields
    message_type  = ProtoField.string("iridium.msg_type", "Message Type"),
    descr_extra   = ProtoField.string("iridium.descr_extra", "Description Extra"),
    error_msg     = ProtoField.string("iridium.error", "Error Message"),
    
    -- Satellite & Network Fields
    satellite     = ProtoField.uint8("iridium.satellite", "Satellite", base.DEC),
    beam          = ProtoField.uint8("iridium.beam", "Beam", base.DEC),
    cell          = ProtoField.uint8("iridium.cell", "Cell", base.DEC),
    slot          = ProtoField.uint8("iridium.slot", "Slot", base.DEC),
    sv_blkn       = ProtoField.uint8("iridium.sv_blkn", "SV Block Number", base.DEC),
    
    -- Location & Positioning Fields
    xyz_coords    = ProtoField.string("iridium.xyz_coords", "XYZ Coordinates"),
    position      = ProtoField.string("iridium.position", "Position (lat/lon)"),
    latitude      = ProtoField.float("iridium.latitude", "Latitude"),
    longitude     = ProtoField.float("iridium.longitude", "Longitude"),
    altitude      = ProtoField.int16("iridium.altitude", "Altitude", base.DEC),
    google_maps   = ProtoField.string("iridium.google_maps", "Google Maps Link"),
    
    -- Access Channel Fields
    aq_cl         = ProtoField.string("iridium.aq_cl", "AQ CL"),
    aq_sb         = ProtoField.uint8("iridium.aq_sb", "AQ SB", base.DEC),
    aq_ch         = ProtoField.uint8("iridium.aq_ch", "AQ CH", base.DEC),
    rai           = ProtoField.uint8("iridium.rai", "RAI", base.DEC),
    bc_sb         = ProtoField.uint8("iridium.bc_sb", "BC SB", base.DEC),
    
    -- Paging & Messaging Fields
    page_info     = ProtoField.string("iridium.page_info", "Page Info"),
    tmsi          = ProtoField.uint32("iridium.tmsi", "TMSI", base.HEX),
    msc_id        = ProtoField.uint8("iridium.msc_id", "MSC ID", base.DEC),
    
    -- IDA Specific Fields (Enhanced)
    lcw_info      = ProtoField.string("iridium.lcw_info", "LCW Info"),
    maintenance   = ProtoField.string("iridium.maintenance", "Maintenance Data"),
    cont          = ProtoField.uint8("iridium.cont", "Cont", base.DEC),
    ctr           = ProtoField.uint16("iridium.ctr", "CTR", base.DEC),
    len           = ProtoField.uint16("iridium.len", "Len", base.DEC),
    lqi           = ProtoField.uint8("iridium.lqi", "LQI", base.DEC),
    power         = ProtoField.int8("iridium.power", "Power", base.DEC),
    f_dtoa        = ProtoField.uint8("iridium.f_dtoa", "F_DTOA", base.DEC),
    f_dfoa        = ProtoField.uint8("iridium.f_dfoa", "F_DFOA", base.DEC),
    
    -- Device Identification (NEW)
    device_id     = ProtoField.uint32("iridium.device_id", "Device ID", base.HEX),
    imei          = ProtoField.string("iridium.imei", "IMEI"),
    device_type   = ProtoField.string("iridium.device_type", "Device Type"),
    
    -- Payload Analysis (NEW)
    sms_payload   = ProtoField.string("iridium.sms_payload", "SMS Payload"),
    data_payload  = ProtoField.bytes("iridium.data_payload", "Data Payload"),
}

iridium_proto.fields = fields

-- 2. UTILITY FUNCTIONS
local function safe_tonumber(str)
    if str and str ~= "" then
        return tonumber(str)
    end
    return nil
end

-- 3. IMPROVED FRAME PARSERS

function parse_raw_frame(data_str, subtree, pinfo)
    -- Remove "Raw Bits: " prefix if present
    local clean_data = string.gsub(data_str, "^Raw Bits:%s*", "")
    
    -- More flexible pattern matching for your actual data format
    -- Based on your sample: "RAW: p-9987-e200 000000613.2889 1616871808 57% -61.21|-109.76|18.10 002 DL <0011001001110010101100011> 1001 ERR:IridiumMessage: Iridium message too short\n"
    
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, binary_data, extra_bits, error_msg = 
        string.match(clean_data, "^(RAW):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%w+)%s*<([^>]*)>%s*(%d*)%s*ERR:(.+)")
    
    if not frame_type then
        -- Try without error message
        frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, binary_data, extra_bits = 
            string.match(clean_data, "^(RAW):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%w+)%s*<([^>]*)>%s*(%d*)")
    end
    
    if not frame_type then
        -- Even more flexible pattern - just get the basics
        frame_type, packet_id, timestamp, frequency, confidence = 
            string.match(clean_data, "^(RAW):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%")
    end
    
    if frame_type and packet_id then
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        subtree:add(fields.timestamp, timestamp .. " ms")
        
        -- Convert and add frequency
        local freq_num = safe_tonumber(frequency)
        if freq_num then
            subtree:add(fields.frequency, freq_num)
        end
        
        -- Convert and add confidence
        local conf_num = safe_tonumber(confidence)
        if conf_num then
            subtree:add(fields.confidence, conf_num)
        end
        
        -- Add signal measurements if available
        if signal and noise and snr then
            local signal_num = safe_tonumber(signal)
            local noise_num = safe_tonumber(noise)
            local snr_num = safe_tonumber(snr)
            
            if signal_num then subtree:add(fields.signal_dbfs, signal_num) end
            if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
            if snr_num then subtree:add(fields.snr_db, snr_num) end
        end
        
        -- Add other fields if available
        if msg_length then
            local length_num = safe_tonumber(msg_length)
            if length_num then
                subtree:add(fields.length, length_num)
            end
        end
        
        if direction then subtree:add(fields.direction, direction) end
        if binary_data then subtree:add(fields.binary_data, binary_data) end
        if extra_bits then subtree:add(fields.extra_bits, extra_bits) end
        if error_msg then subtree:add(fields.error_msg, error_msg) end
        
        -- Set info column with key details
        local info_parts = {}
        table.insert(info_parts, frame_type .. ": " .. packet_id)
        
        if freq_num then
            table.insert(info_parts, string.format("%.3f MHz", freq_num/1000000))
        end
        
        if conf_num then
            table.insert(info_parts, conf_num .. "%")
        end
        
        if direction then
            table.insert(info_parts, direction)
        end
        
        if error_msg then
            table.insert(info_parts, "ERR")
        end
        
        pinfo.cols.info = table.concat(info_parts, ", ")
        
    else
        -- Fallback - just show the raw data
        subtree:add(fields.raw_data, clean_data)
        pinfo.cols.info = "RAW Frame (parse failed)"
        
        -- Add debug info to help troubleshoot
        local debug_tree = subtree:add("iridium.debug", "Debug Info")
        debug_tree:add("iridium.debug.original", data_str)
        debug_tree:add("iridium.debug.cleaned", clean_data)
    end
end

function parse_iip_frame(data_str, subtree, pinfo)
    -- Parse IIP frames with enhanced field extraction
    -- Format: IIP: station timestamp frequency confidence signal|noise|snr length direction LCW(...) type:XX seq=XXX ack=XXX ... IP: decoded_message
    
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, remaining = 
        string.match(data_str, "^(IIP):%s+(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%S+)%s+(.*)")
    
    if frame_type and packet_id then
        -- Add basic frame info
        subtree:add(fields.frame_type, "IIP")
        subtree:add(fields.packet_id, packet_id)
        
        local timestamp_num = safe_tonumber(timestamp)
        if timestamp_num then subtree:add(fields.timestamp, timestamp_num) end
        
        local freq_num = safe_tonumber(frequency)
        if freq_num then subtree:add(fields.frequency, freq_num) end
        
        local conf_num = safe_tonumber(confidence)
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        local sig_num = safe_tonumber(signal)
        if sig_num then subtree:add(fields.signal_dbfs, sig_num) end
        
        local noise_num = safe_tonumber(noise)
        if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
        
        local snr_num = safe_tonumber(snr)
        if snr_num then subtree:add(fields.snr_db, snr_num) end
        
        local len_num = safe_tonumber(msg_length)
        if len_num then subtree:add(fields.length, len_num) end
        
        subtree:add(fields.direction, direction)
        
        if remaining then
            -- Extract position from signal|noise|snr
            local position_str = signal .. "|" .. noise .. "|" .. snr
            subtree:add(fields.position, position_str)
            
            -- Extract LCW info: LCW(1,T:hndof,C:handoff_cand,...)
            local lcw_info = string.match(remaining, "(LCW%([^%)]+%))")
            if lcw_info then
                subtree:add(fields.lcw_info, lcw_info)
            end
            
            -- Extract IIP type: type:04
            local iip_type = string.match(remaining, "type:(%w+)")
            if iip_type then
                subtree:add(fields.message_type, "Type:" .. iip_type)
            end
            
            -- Extract sequence: seq=136
            local seq = string.match(remaining, "seq=(%d+)")
            if seq then
                local seq_num = safe_tonumber(seq)
                if seq_num then subtree:add(fields.ctr, seq_num) end
            end
            
            -- Extract ack: ack=005
            local ack = string.match(remaining, "ack=(%d+)")
            if ack then
                subtree:add(fields.descr_extra, "ACK:" .. ack)
            end
            
            -- Extract checksum/FCS: cs=110/0 K or FCS:OK
            local checksum = string.match(remaining, "cs=(%S+)")
            if checksum then
                subtree:add(fields.frame_status, "CS:" .. checksum)
            end
            
            local fcs = string.match(remaining, "FCS:(%S+)")
            if fcs then
                subtree:add(fields.frame_status, "FCS:" .. fcs)
            end
            
            -- Extract len field: len=031
            local len_field = string.match(remaining, "len=(%d+)")
            if len_field then
                local len_num = safe_tonumber(len_field)
                if len_num then subtree:add(fields.len, len_num) end
            end
            
            -- Extract hex payload in brackets: [49.50.3a.20...]
            local hex_payload = string.match(remaining, "%[([%x%.%s]+)%]")
            if hex_payload then
                subtree:add(fields.hex_payload, hex_payload)
            end
            
            -- Extract decoded message after "IP: "
            local decoded_msg = string.match(remaining, "IP:%s*(.+)$")
            if decoded_msg and decoded_msg ~= "" then
                subtree:add(fields.sms_payload, decoded_msg)
            end
        end
        
        -- Update info column
        if pinfo then
            local info = string.format("IIP: %s %.3f MHz %s%% %s",
                packet_id or "?",
                (freq_num and freq_num/1000000) or 0,
                confidence or "?",
                direction or "?"
            )
            
            -- Add decoded message preview if available
            local decoded_preview = string.match(data_str, "IP:%s*(.+)$")
            if decoded_preview and decoded_preview ~= "" then
                -- Limit preview to 50 chars
                if string.len(decoded_preview) > 50 then
                    decoded_preview = decoded_preview:sub(1, 47) .. "..."
                end
                info = info .. " | " .. decoded_preview
            end
            
            pinfo.cols.info = info
        end
    else
        subtree:add(fields.raw_data, data_str)
        pinfo.cols.info = "IIP Frame (parse failed)"
    end
end

function parse_iri_frame(data_str, subtree, pinfo)
    -- Parse IRI frames - try multiple patterns
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, msg_type, remaining = 
        string.match(data_str, "^(IRI):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%w+)%s+([^%s]+)%s*(.*)")
    
    if not frame_type then
        -- Try simpler pattern
        frame_type, packet_id, timestamp, frequency, confidence = 
            string.match(data_str, "^(IRI):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%")
    end
    
    if frame_type and packet_id then
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        subtree:add(fields.timestamp, timestamp .. " ms")
        
        local freq_num = safe_tonumber(frequency)
        local conf_num = safe_tonumber(confidence)
        
        if freq_num then subtree:add(fields.frequency, freq_num) end
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        if signal and noise and snr then
            local signal_num = safe_tonumber(signal)
            local noise_num = safe_tonumber(noise)
            local snr_num = safe_tonumber(snr)
            
            if signal_num then subtree:add(fields.signal_dbfs, signal_num) end
            if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
            if snr_num then subtree:add(fields.snr_db, snr_num) end
        end
        
        if msg_length then
            local length_num = safe_tonumber(msg_length)
            if length_num then subtree:add(fields.length, length_num) end
        end
        
        if direction then subtree:add(fields.direction, direction) end
        if msg_type then subtree:add(fields.message_type, msg_type) end
        
        -- Parse remaining data for hex payload, descr_extra, and errors
        if remaining then
            local hex_payload = string.match(remaining, "%[([%x%.]+)%]")
            if hex_payload then
                subtree:add(fields.hex_payload, hex_payload)
            end
            
            local descr_extra = string.match(remaining, "descr_extra:([01]+)")
            if descr_extra then
                subtree:add(fields.descr_extra, descr_extra)
            end
            
            local error_msg = string.match(remaining, "ERR:(.+)")
            if error_msg then
                subtree:add(fields.error_msg, error_msg)
            end
        end
        
        -- Set info column
        local info_parts = {}
        table.insert(info_parts, frame_type .. ": " .. packet_id)
        
        if freq_num then
            table.insert(info_parts, string.format("%.3f MHz", freq_num/1000000))
        end
        
        if conf_num then
            table.insert(info_parts, conf_num .. "%")
        end
        
        if direction and msg_type then
            table.insert(info_parts, direction .. " " .. msg_type)
        end
        
        pinfo.cols.info = table.concat(info_parts, ", ")
        
    else
        subtree:add(fields.raw_data, data_str)
        pinfo.cols.info = "IRI Frame (parse failed)"
    end
end
function parse_ibc_frame(data_str, subtree, pinfo)
    -- Parse IBC frames: IBC: p-9987-e212 000004419.8754 1617400960 58% -67.96|-109.47|24.01 066 DL bc:1
    
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, remaining = 
        string.match(data_str, "^(IBC):%s+(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%S+)%s+(.*)")
    
    if not frame_type then
        -- Try alternative pattern without length field
        frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, direction, remaining = 
            string.match(data_str, "^(IBC):%s+(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%S+)%s+(.*)")
    end
    
    if frame_type and packet_id then
        -- Add basic parsed fields
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        subtree:add(fields.timestamp, timestamp .. " ms")
        
        local freq_num = safe_tonumber(frequency)
        if freq_num then subtree:add(fields.frequency, freq_num) end
        
        local conf_num = safe_tonumber(confidence)
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        local signal_num = safe_tonumber(signal)
        if signal_num then subtree:add(fields.signal_dbfs, signal_num) end
        
        local noise_num = safe_tonumber(noise)
        if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
        
        local snr_num = safe_tonumber(snr)
        if snr_num then subtree:add(fields.snr_db, snr_num) end
        
        if msg_length then
            local length_num = safe_tonumber(msg_length)
            if length_num then subtree:add(fields.length, length_num) end
        end
        
        if direction then subtree:add(fields.direction, direction) end
        
        -- Parse IBC-specific fields
        if remaining then
            local bc_info = string.match(remaining, "(bc:%d+)")
            if bc_info then 
                subtree:add(fields.message_type, bc_info)
            end
            
            -- Add other field extractions as needed...
        end
        
        -- Update info column
        pinfo.cols.info = string.format("IBC: %s %.3f MHz %s%% %s %s",
            packet_id,
            (freq_num and freq_num/1000000) or 0,
            confidence or "?",
            direction or "?",
            bc_info or ""
        )
    else
        subtree:add(fields.raw_data, data_str)
        pinfo.cols.info = "IBC Frame (parse failed)"
    end
end
function parse_ida_frame(data_str, subtree, pinfo)
    -- Parse IDA frames
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, remaining = 
        string.match(data_str, "^(IDA):%s+(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%S+)%s+(.*)")
    
    if frame_type and packet_id then
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        subtree:add(fields.timestamp, timestamp .. " ms")
        
        local freq_num = safe_tonumber(frequency)
        if freq_num then subtree:add(fields.frequency, freq_num) end
        
        local conf_num = safe_tonumber(confidence)
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        local signal_num = safe_tonumber(signal)
        if signal_num then subtree:add(fields.signal_dbfs, signal_num) end
        
        local noise_num = safe_tonumber(noise)
        if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
        
        local snr_num = safe_tonumber(snr)
        if snr_num then subtree:add(fields.snr_db, snr_num) end
        
        local length_num = safe_tonumber(msg_length)
        if length_num then subtree:add(fields.length, length_num) end
        
        subtree:add(fields.direction, direction)
        
        -- Parse IDA-specific fields
        if remaining then
            -- Extract full LCW info
            local lcw_info = string.match(remaining, "(LCW%([^%)]*%))")
            if lcw_info then
                subtree:add(fields.lcw_info, lcw_info)
            end
            
            -- Extract maintenance data
            local maint_data = string.match(remaining, "maint%[([^%]]+)%]")
            if maint_data then
                subtree:add(fields.maintenance, maint_data)
            end
            
            -- Extract LQI, power, f_dtoa, f_dfoa values
            local lqi = string.match(remaining, "lqi:(%d+)")
            if lqi then subtree:add(fields.lqi, tonumber(lqi)) end
            
            local power = string.match(remaining, "power:([%d%-]+)")
            if power then subtree:add(fields.power, tonumber(power)) end
            
            local f_dtoa = string.match(remaining, "f_dtoa:(%d+)")
            if f_dtoa then subtree:add(fields.f_dtoa, tonumber(f_dtoa)) end
            
            local f_dfoa = string.match(remaining, "f_dfoa:(%d+)")
            if f_dfoa then subtree:add(fields.f_dfoa, tonumber(f_dfoa)) end
        end
        
        pinfo.cols.info = string.format("IDA: %s %.3f MHz %s%% %s LCW",
            packet_id,
            (freq_num and freq_num/1000000) or 0,
            confidence or "?",
            direction or "?"
        )
    else
        subtree:add(fields.raw_data, data_str)
        pinfo.cols.info = "IDA Frame (parse failed)"
    end
end
function parse_isy_frame(data_str, subtree, pinfo)
    -- Parse ISY frames: ISY: p-9987-e239 000610333.2591 1624961536 55% -73.15|-110.21|22.38 044 DL LCW(7,T:rsrvd,C:<5>,0001000010110110100110)
    
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, remaining = 
        string.match(data_str, "^(ISY):%s+(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%S+)%s+(.*)")
    
    if frame_type and packet_id then
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        subtree:add(fields.timestamp, timestamp .. " ms")
        
        local freq_num = safe_tonumber(frequency)
        if freq_num then subtree:add(fields.frequency, freq_num) end
        
        local conf_num = safe_tonumber(confidence)
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        local signal_num = safe_tonumber(signal)
        if signal_num then subtree:add(fields.signal_dbfs, signal_num) end
        
        local noise_num = safe_tonumber(noise)
        if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
        
        local snr_num = safe_tonumber(snr)
        if snr_num then subtree:add(fields.snr_db, snr_num) end
        
        local length_num = safe_tonumber(msg_length)
        if length_num then subtree:add(fields.length, length_num) end
        
        subtree:add(fields.direction, direction)
        
        -- Extract LCW info
        if remaining then
            local lcw_info = string.match(remaining, "(LCW%([^%)]*%))")
            if lcw_info then
                subtree:add(fields.lcw_info, lcw_info)
            end
        end
        
        pinfo.cols.info = string.format("ISY: %s %.3f MHz %s%% %s %s",
            packet_id,
            (freq_num and freq_num/1000000) or 0,
            confidence or "?",
            direction or "?",
            lcw_info or ""
        )
    else
        subtree:add(fields.raw_data, data_str)
        pinfo.cols.info = "ISY Frame (parse failed)"
    end
end
function parse_ira_frame(data_str, subtree, pinfo)
    -- Parse IRA frames based on your actual format:
    -- IRA: p-9987-e205 000673190.9400 1615911808  59% -69.12|-110.10|20.68 125 DL sat:120 beam:40 xyz=(-0196,+2020,-1183) pos=(-30.24/+095.54) alt=3041 RAI:106 ?11 bc_sb:13 P01: PAGE(tmsi:aa9e7305 0:1 msc_id:25 0:7) {TRUNCATED}
    
    -- Main pattern to extract header info
    local frame_type, packet_id, timestamp, frequency, confidence, signal, noise, snr, msg_length, direction, remaining = 
        string.match(data_str, "^(IRA):%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+(%d+)%%%s+([%d%-%.]+)|([%d%-%.]+)|([%d%-%.]+)%s+(%d+)%s+(%w+)%s+(.+)")
    
    if frame_type then
        -- Add basic frame info
        subtree:add(fields.frame_type, frame_type)
        subtree:add(fields.packet_id, packet_id)
        
        local timestamp_num = safe_tonumber(timestamp)
        if timestamp_num then subtree:add(fields.timestamp, timestamp_num) end
        
        local freq_num = safe_tonumber(frequency)
        if freq_num then subtree:add(fields.frequency, freq_num) end
        
        local conf_num = safe_tonumber(confidence)
        if conf_num then subtree:add(fields.confidence, conf_num) end
        
        local sig_num = safe_tonumber(signal)
        if sig_num then subtree:add(fields.signal_dbfs, sig_num) end
        
        local noise_num = safe_tonumber(noise)
        if noise_num then subtree:add(fields.noise_dbfs, noise_num) end
        
        local snr_num = safe_tonumber(snr)
        if snr_num then subtree:add(fields.snr_db, snr_num) end
        
        local len_num = safe_tonumber(msg_length)
        if len_num then subtree:add(fields.length, len_num) end
        
        subtree:add(fields.direction, direction)
        
        if remaining then
            -- Extract satellite: sat:120
            local satellite = string.match(remaining, "sat:(%d+)")
            if satellite then
                local sat_num = safe_tonumber(satellite)
                if sat_num then subtree:add(fields.satellite, sat_num) end
            end
            
            -- Extract beam: beam:40
            local beam = string.match(remaining, "beam:(%d+)")
            if beam then
                local beam_num = safe_tonumber(beam)
                if beam_num then subtree:add(fields.beam, beam_num) end
            end
            
            -- Extract xyz coordinates: xyz=(-0196,+2020,-1183)
            local xyz = string.match(remaining, "xyz=%(([^%)]+)%)")
            if xyz then
                subtree:add(fields.xyz_coords, xyz)
            end
            
            -- Extract position: pos=(-30.24/+095.54)
            local lat_str, lon_str = string.match(remaining, "pos=%(([%+%-]?[%d%.]+)/([%+%-]?[%d%.]+)%)")
            if lat_str and lon_str then
                local lat_num = safe_tonumber(lat_str)
                local lon_num = safe_tonumber(lon_str)
                if lat_num and lon_num then
                    subtree:add(fields.latitude, lat_num)
                    subtree:add(fields.longitude, lon_num)
                    subtree:add(fields.position, lat_str .. "/" .. lon_str)
                    
                    -- Create clickable Google Maps link
                    local url_str = "https://www.openstreetmap.org/?mlat=" .. string.format("%.5f", lat_num) .. "&mlon=" .. string.format("%.5f", lon_num) .. "&zoom=12"
                    local maps_item = subtree:add(url_str)
                    maps_item:set_text("[Location OSM URI: " .. url_str .. "]")
                end
            end
            
            -- Extract altitude: alt=3041
            local altitude = string.match(remaining, "alt=(%d+)")
            if altitude then
                local alt_num = safe_tonumber(altitude)
                if alt_num then subtree:add(fields.altitude, alt_num) end
            end
            
            -- Extract RAI: RAI:106
            local rai = string.match(remaining, "RAI:(%d+)")
            if rai then
                local rai_num = safe_tonumber(rai)
                if rai_num then subtree:add(fields.rai, rai_num) end
            end
            
            -- Extract TMSI from PAGE(tmsi:aa9e7305 ...) pattern
            local tmsi_hex = string.match(remaining, "tmsi:([%da-fA-F]+)")
            if tmsi_hex then
                local tmsi_num = tonumber(tmsi_hex, 16)
                if tmsi_num then subtree:add(fields.tmsi, tmsi_num) end
            end
            
            -- Extract MSC ID from msc_id:25 pattern  
            local msc_id = string.match(remaining, "msc_id:(%d+)")
            if msc_id then
                local msc_id_num = safe_tonumber(msc_id)
                if msc_id_num then subtree:add(fields.msc_id, msc_id_num) end
            end
            
            -- Extract bc_sb: bc_sb:13
            local bc_sb = string.match(remaining, "bc_sb:(%d+)")
            if bc_sb then
                local bc_sb_num = safe_tonumber(bc_sb)
                if bc_sb_num then subtree:add(fields.bc_sb, bc_sb_num) end
            end
            
            -- Extract page info
            local page_info = string.match(remaining, "(P%d+:.*)")
            if page_info then
                subtree:add(fields.page_info, page_info)
            end
        end
        
        -- Update info column
        if pinfo then
            pinfo.cols.info = string.format("IRA: %s %.3f MHz %s%% %s sat:%s pos:%s/%s TMSI:%s MSC:%s",
                packet_id or "?",
                (freq_num and freq_num/1000000) or 0,
                confidence or "?",
                direction or "?",
                satellite or "?",
                lat_str or "?",
                lon_str or "?",
                tmsi_hex or "?",
                msc_id or "?"
            )
        end
    end
end

function parse_generic_frame(data_str, subtree, pinfo)
    -- Generic parser for any unrecognized frame
    subtree:add(fields.raw_data, data_str)
    
    -- Try to extract basic frame type at least
    local frame_type = string.match(data_str, "^(%a+):")
    if frame_type then
        subtree:add(fields.frame_type, frame_type)
        pinfo.cols.info = frame_type .. " Frame"
    else
        pinfo.cols.info = "Iridium Frame (generic)"
    end
    
    return true
end

-- 4. FRAME PARSER MAPPING
local frame_parsers = {
    RAW = parse_raw_frame,
    IRI = parse_iri_frame,
    IIP = parse_iip_frame,  -- Dedicated IIP parser with enhanced decoding
    IBC = parse_ibc_frame,  -- Use same parser for now
    IRA = parse_ira_frame,  -- Now has its own specialized parser
    IDA = parse_ida_frame,  -- Use same parser for now
    ISY = parse_isy_frame,  -- Use same parser for now
    IU3 = parse_iri_frame,  -- Use same parser for now
    IME = parse_iri_frame,  -- Use same parser for now
}

-- 5. MAIN DISSECTOR FUNCTION
function iridium_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = iridium_proto.name
    local data_str = buffer():string()
    local subtree = tree:add(iridium_proto, buffer(), "Iridium Satellite Data (" .. length .. " bytes)")
    
    -- Debug: Add raw data to see what we're working with
    local debug_tree = subtree:add("iridium.debug", "Debug Info")
    debug_tree:add("iridium.debug.raw", data_str)
    
    -- Check for "Raw Bits: " prefix first
    if string.match(data_str, "^Raw Bits:%s*") then
        parse_raw_frame(data_str, subtree, pinfo)
        return
    end
    
    -- Then check for standard frame types
    local frame_type = string.match(data_str, "^(%a+):")
    
    if frame_type and frame_parsers[frame_type] then
        frame_parsers[frame_type](data_str, subtree, pinfo)
    else
        parse_generic_frame(data_str, subtree, pinfo)
    end
end

-- 6. REGISTRATION
local udp_port = DissectorTable.get("udp.port")
udp_port:add(15007, iridium_proto)
udp_port:add_for_decode_as(iridium_proto)