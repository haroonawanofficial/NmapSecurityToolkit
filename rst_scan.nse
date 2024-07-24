-- Enhanced Nmap Script for Stealthy and Effective TCP Port Scanning
-- This script uses advanced techniques to minimize detection and maximize effectiveness in scanning through firewalls.

description = [[
  This script performs a highly stealthy TCP scan to identify open ports on a target system using advanced techniques.
  It incorporates RST scanning, passive scanning, and evasion strategies to avoid detection by WAFs, firewalls, IDS, or IPS.
]]

author = "Haroon Ahmad Awan <haroon@cyberzeus.pk>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "stealth"}

require 'nmap'
require 'shortport'
require 'stdnse'
require 'packet'

portrule = shortport.port_or_service({1, 65535}, nil)

-- Command line arguments for user customization
local function parse_args()
  local args = nmap.registry.args
  local dummy_ip = args.dummy_ip
  local start_port = tonumber(args.start_port) or 1
  local end_port = tonumber(args.end_port) or 65535
  local interface = args.interface or "ppp0"
  
  if not dummy_ip then
    stdnse.print_debug("Missing required argument: dummy_ip")
    return nil
  end
  
  return dummy_ip, start_port, end_port, interface
end

-- Function to send packets with optional flags and ports
local function send_packet(ip, saddr, daddr, sport, dport, flags, ttl, window)
  local pkt = packet.Packet:new()
  pkt.ip_bin = packet.iptobin(saddr)
  pkt.ip_bin_dst = packet.iptobin(daddr)
  pkt:build_tcp(dport, sport)
  pkt.tcp_flags = flags
  pkt.ip_ttl = ttl or 64
  pkt.tcp_window = window or 8192
  pkt:ip_checksum()
  pkt:tcp_checksum()
  pkt:send(ip)
end

-- Function to perform passive scanning
local function passive_scan(ip, timeout)
  local pcap = nmap.new_pcap()
  pcap:set_timeout(timeout)
  pcap:open(ip, 1024, false, "tcp and src host " .. ip)
  local packets = {}

  local status, _, pkt = pcap:pcap_receive()
  while status do
    local response = packet.Packet:new(pkt, #pkt)
    table.insert(packets, response)
    status, _, pkt = pcap:pcap_receive()
  end
  
  pcap:close()
  return packets
end

-- Function to analyze incoming packets and detect port states
local function analyze_packets(packets)
  local seqs = {}
  for _, pkt in ipairs(packets) do
    if pkt.tcp_flags.R then
      table.insert(seqs, pkt.ip_id)
    end
  end
  return seqs
end

-- Function to check for consistent IP ID increments
local function check_increments(seqs)
  local diff = seqs[2] - seqs[1]
  for i = 2, #seqs - 1 do
    if seqs[i + 1] - seqs[i] ~= diff then
      return false, diff
    end
  end
  return true, diff
end

-- Action function for performing the scan
action = function(host, port)
  local dummy_ip, start_port, end_port, interface = parse_args()
  if not dummy_ip then
    return "Missing required arguments"
  end

  local my_ip = nmap.get_interface_info(interface).address
  local open_ports = {}

  stdnse.print_debug("Scanning Dumb Host (for Dumbness)")
  for i = 1, 4 do
    stdnse.sleep(math.random(1, 3))  -- Randomize sleep to evade detection
    send_packet(interface, my_ip, dummy_ip, 0, 0, "A")
  end
  
  local packets = passive_scan(interface, 30)
  local seqs = analyze_packets(packets)
  local consistent, diff = check_increments(seqs)

  if not consistent then
    return "Dumb host not dumb enough... exiting."
  end

  stdnse.print_debug("We have a consistent %d increment host", diff)
  stdnse.print_debug("*** Injecting Spoofed Packet ***")

  for port = start_port, end_port do
    for i = 1, 4 do
      stdnse.sleep(math.random(1, 3))  -- Randomize sleep to evade detection
      send_packet(interface, my_ip, dummy_ip, 0, 0, "A")
      send_packet(interface, dummy_ip, host.ip, 80, port, "S", math.random(32, 128), math.random(1024, 65535))
    end
    
    packets = passive_scan(interface, 30)
    seqs = analyze_packets(packets)
    consistent, _ = check_increments(seqs)

    if not consistent then
      table.insert(open_ports, port)
      stdnse.print_debug("*** Yup looks like port %d is open on %s ***", port, host.ip)
    else
      stdnse.print_debug("Nope... doesn't look like port %d is open on %s", port, host.ip)
    end
  end

  return open_ports
end
