---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

-- there are over 200 modules available to tune your policy.
-- many can be used with defaults w/o any explicit configuration.
-- use this conf as a template for your specific configuration.
-- 1. configure defaults
-- 2. configure inspection
-- 3. configure bindings
-- 4. configure performance
-- 5. configure detection
-- 6. configure filters
-- 7. configure outputs
-- 8. configure tweaks

---------------------------------------------------------------------------
-- 1. configure defaults
---------------------------------------------------------------------------

-- HOME_NET and EXTERNAL_NET must be set now
-- setup the network addresses you are protecting
-- HOME_NET = 'any'

HOME_NET = [[ 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12 ]]

-- set up the external network addresses.
-- (leave as "any" in most situations)
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'
include 'file_magic.lua'

---------------------------------------------------------------------------
-- 2. configure inspection
---------------------------------------------------------------------------

-- mod = { } uses internal defaults
-- you can see them with snort --help-module mod

-- mod = default_mod uses external defaults
-- you can see them in snort_defaults.lua

-- the following are quite capable with defaults:

stream = { }
stream_ip = 
{ 
    session_timeout = 180, --session tracking timeout
    policy = windows, -- fragment reassembly policy {first | linux | bsd | bds_right | last | windows | solaris }
}
stream_icmp = { }
stream_tcp = 
{
--    max_windows = 0, -- 1073725440 is maximum allowed or set to 0 --> err
    max_pdu = 32768, -- maximum reassembler PDU size {1460:32768}
    policy = windows, -- determine operating system characteristic like assembly { first | last | linux | old_linux | bsd | macos| solaris | irix | hpux11 | hpux10 | windows | win_2003 | vista | proxy }
    session_timeout = 180,
}
stream_udp = 
{
    session_timeout = 180,
}
stream_user = 
{
    session_timeout = 360,
}
stream_file = 
{
    upload = true,  -- indicate file transfer direction
}

arp_spoof = { }
back_orifice = { }
dnp3 = { }
dns = { }
http_inspect = 
{
    unzip = true, -- decompress gzip and deflate message bodies
    normalize_utf = true, -- normalize charset UTF encodings in response bodies
    decompress_pdf = true, -- decompress pdf file in the response bodies
    decompress_swf = true,
    decompress_zip = true,
    detained_inspection = true, -- store and forward as necessary to effectively block alerting JavaScript
    script_detection = true, -- inspect JavaScript immediately upon script end
    normalize_javascript = true, -- normalize JavaScript in response bodies
    percent_u = true, -- normalize %uNNNN and %UNNNN endcoding
    utf8_bare_byte = true, -- when doing UTF-8 character normalization include bytes that were not percent encoded
    oversize_dir_length = 65535, -- Length for URL directory
--    show_scan = true,
}
http2_inspect = 
{
--    show_scan = true,
}
imap = 
{
    decompress_pdf = true,
    decompress_swf = true,
    decompress_zip = true,
}
modbus = { }
netflow = 
{
    dump_file = '/var/log/snort/dump_flow'
}
normalizer = { }
pop = 
{
	decompress_pdf = true,
	decompress_swf = true,
	decompress_zip = true, 
}
rpc_decode = { }
sip = { }
ssh = { }
ssl = 
{ 
	max_heartbeat_length = 65535, --maximum length of heartbeat record allowed
}
telnet = 
{
    ayt_attack_thresh = 65535, -- alert on this number of consecutive Telnet AYT commands {-1:2147483647}
--    check_encrypted = true, -- check for end of encrytion --> err
    encrypted_traffic = true, -- check for endcrypted Telnet
    normalize = true, -- eliminate escape sequences
}

dce_smb = 
{
	smb_fingerprint_policy = both, -- target base SMB policy to use { none | client | server | both } 
	policy = Win7,
	smb_max_chain = 255,
	smb_max_compound = 255,
	smb_file_inspection = on,
	smb_file_depth = 0, -- unlimited
	smb_legacy_mode = true,
}
dce_tcp = 
{
	policy = Win7, 
}
dce_udp = { }
dce_http_proxy = { }
dce_http_server = { }

-- see snort_defaults.lua for default_*
gtp_inspect = default_gtp
port_scan = default_med_port_scan

smtp = 
{
-- default_smtp
	decompress_pdf = true,
	decompress_swf = true,
	decompress_zip = true,
	b64_decode_depth = -1, -- no limit
	bitenc_decode_depth = -1, -- no limit
	log_email_hdrs = true, -- log the SMTP email header extracted from SMTP Data
	log_filename = true, -- log the MIME attachment filenames extracted from the Content-Disposition header within the MIME body
	log_mailfrom = true, -- log the sender
	log_rcptto = true, --log the recipient's email address
	max_auth_command_line_len = 65535,
	max_command_line_len = 65535,
	max_header_line_len = 65535,
	max_response_line_len = 65535,
	normalize = all,
}

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

-- see file_magic.lua for file id rules
file_id =
{
	enable_type = true,
	enable_signature = true,
	enable_capture = true,
	trace_type = true,
	trace_signature = true,
	trace_stream = true,
	file_rules = file_magic,
	file_policy =
		{
			{ use = { verdict = 'log', enable_file_type = true, enable_file_capture = true, enable_file_signature = true } }
		}
}

appid =
{
	log_stats = true,
	app_detector_dir = '/usr/local/snort/appid'
--	list_odp_detectors = true,
--	log_all_sessions = true,
}
-- End of Add for running with ElasticSearch, LogStash, and Kibana

reputation =
{
	-- configure one or both of these, then uncomment reputation
--	blacklist = '/usr/local/snort/intel/ip-blocklist',
-- whitelist = PASS_LIST_PATH .. '/ip-passlist'

	blocklist = '/usr/local/snort/intel/ip-blocklist'
--	list_dir = '/usr/local/snort/intel'


}

process =
{
	--same as -D
	daemon = true,
	--same as -u
	set_uid = 'snort',
	--same as -g
	set_gid = 'snort',
	utc = true
}

---------------------------------------------------------------------------
-- 3. configure bindings
---------------------------------------------------------------------------

wizard = default_wizard

binder =
{
    -- port bindings required for protocols without wizard support
    { when = { proto = 'udp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111', role='server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502', role='server' }, use = { type = 'modbus' } },
    { when = { proto = 'tcp', ports = '2123 2152 3386', role='server' }, use = { type = 'gtp_inspect' } },

    { when = { proto = 'tcp', service = 'dcerpc' }, use = { type = 'dce_tcp' } },
    { when = { proto = 'udp', service = 'dcerpc' }, use = { type = 'dce_udp' } },
    { when = { proto = 'udp', service = 'netflow' }, use = { type = 'netflow' } },

    { when = { service = 'netbios-ssn' },      use = { type = 'dce_smb' } },
    { when = { service = 'dce_http_server' },  use = { type = 'dce_http_server' } },
    { when = { service = 'dce_http_proxy' },   use = { type = 'dce_http_proxy' } },

    { when = { service = 'dnp3' },             use = { type = 'dnp3' } },
    { when = { service = 'dns' },              use = { type = 'dns' } },
    { when = { service = 'ftp' },              use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data' },         use = { type = 'ftp_data' } },
    { when = { service = 'gtp' },              use = { type = 'gtp_inspect' } },
    { when = { service = 'imap' },             use = { type = 'imap' } },
    { when = { service = 'http' },             use = { type = 'http_inspect' } },
    { when = { service = 'http2' },            use = { type = 'http2_inspect' } },
    { when = { service = 'modbus' },           use = { type = 'modbus' } },
    { when = { service = 'pop3' },             use = { type = 'pop' } },
    { when = { service = 'ssh' },              use = { type = 'ssh' } },
    { when = { service = 'sip' },              use = { type = 'sip' } },
    { when = { service = 'smtp' },             use = { type = 'smtp' } },
    { when = { service = 'ssl' },              use = { type = 'ssl' } },
    { when = { service = 'sunrpc' },           use = { type = 'rpc_decode' } },
    { when = { service = 'telnet' },           use = { type = 'telnet' } },

    { use = { type = 'wizard' } }
}

---------------------------------------------------------------------------
-- 4. configure performance
---------------------------------------------------------------------------

-- use latency to monitor / enforce packet and rule thresholds
--latency = { }

-- use these to capture perf data for analysis and tuning
--profiler = { }
--perf_monitor = { }

---------------------------------------------------------------------------
-- 5. configure detection
---------------------------------------------------------------------------

references = default_references
classifications = default_classifications

ips =
{
    mode = tap,
	variables =
    {
        nets =
        {
            EXTERNAL_NET = EXTERNAL_NET,
            HOME_NET = HOME_NET
        },
        ports =
        {
            HTTP_PORTS = HTTP_PORTS
        }
    },
	rules = [[
		include $RULE_PATH/snort.rules
			]],
	variables = default_variables,
}

rewrite = { }

-- use these to configure additional rule actions
-- react = { }
-- reject = { }

-- use this to enable payload injection utility
-- payload_injector = { }

---------------------------------------------------------------------------
-- 6. configure filters
---------------------------------------------------------------------------

-- below are examples of filters
-- each table is a list of records

--[[
suppress =
{
    -- don't want to any of see these
    { gid = 1, sid = 1 },

    -- don't want to see these for a given server
    { gid = 1, sid = 2, track = 'by_dst', ip = '1.2.3.4' },
}
--]]

--[[
event_filter =
{
    -- reduce the number of events logged for some rules
    { gid = 1, sid = 1, type = 'limit', track = 'by_src', count = 2, seconds = 10 },
    { gid = 1, sid = 2, type = 'both',  track = 'by_dst', count = 5, seconds = 60 },
}
--]]

--[[
rate_filter =
{
    -- alert on connection attempts from clients in SOME_NET
    { gid = 135, sid = 1, track = 'by_src', count = 5, seconds = 1,
      new_action = 'alert', timeout = 4, apply_to = '[$SOME_NET]' },

    -- alert on connections to servers over threshold
    { gid = 135, sid = 2, track = 'by_dst', count = 29, seconds = 3,
      new_action = 'alert', timeout = 1 },
}
--]]

---------------------------------------------------------------------------
-- 7. configure outputs
---------------------------------------------------------------------------

-- event logging
-- you can enable with defaults from the command line with -A <alert_type>
-- uncomment below to set non-default configs
alert_csv = 
{
	file = true
}

alert_fast =
{
	file = true,
	packet = true, --output packet dump with alert
	limit = 1024, -- Maximum size in MB before rollover
}

file_log =
{
	log_pkt_time = true,
	log_sys_time = false
}

alert_full = 
{
	file = true,
	limit = 1024, 
}

alert_sfsocket = 
{ 
	file = '/var/log/snort/sfsocket.alert'
}

alert_syslog = 
{
	level = info,
	facility = daemon,
	options = 'cons' 
}

alert_json =
{
	file = true,
	limit = 1024,
	fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr eth_src src_port dst_addr eth_dst dst_port service rule priority class action b64_data'
	
}

unified2 = 
{
	legacy_events = true,
	nostamp = false 
}

-- packet logging
-- you can enable with defaults from the command line with -L <log_type>
log_codecs = 
{
	file = true,
	msg = true
}

log_hext = 
{ 
	file = true,
	raw = true
}

log_pcap = 
{
	limit = 1024 
}

packet_capture = 
{
	enable = true 
}


---------------------------------------------------------------------------
-- 8. configure tweaks
---------------------------------------------------------------------------

if ( tweaks ~= nil ) then
    include(tweaks .. '.lua')
end

