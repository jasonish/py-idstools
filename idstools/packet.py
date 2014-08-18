# Copyright (c) 2014 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Provides basic packet decoding."""

import struct
import socket

ETHERTYPE_IP = 0x0800

ETHER_HDR_LEN = 14
IP_HDR_LEN    = 20
ICMP4_HDR_LEN = 4
UDP_HDR_LEN   = 8
TCP_HDR_LEN   = 20

def printable_ethernet_addr(addr):
    """Return a formatted ethernet address from its raw form."""
    return ":".join(["%02x" % (x) for x in struct.unpack("BBBBBB", addr)])
    
def decode_icmp(pkt):
    """ Decode an ICMP packet. """
    icmp = {}

    (icmp["icmp_type"],
     icmp["icmp_code"],
     icmp["icmp_chksum"]) = struct.unpack(">BBH", pkt[0:ICMP4_HDR_LEN])

    icmp["icmp_payload"] = pkt[ICMP4_HDR_LEN:]

    return icmp

def decode_udp(pkt):
    """Decode a UDP packet."""
    udp = {}

    (udp["udp_sport"],
     udp["udp_dport"],
     udp["udp_length"],
     udp["udp_chksum"]) = struct.unpack(">HHHH", pkt[0:UDP_HDR_LEN])

    udp["udp_payload"] = pkt[UDP_HDR_LEN:]

    return udp

def decode_tcp(pkt):
    """Decode a TCP packet."""
    tcp = {}

    (tcp["tcp_sport"],
     tcp["tcp_dport"],
     tcp["tcp_seq"],
     tcp["tcp_ack"],
     tcp["tcp_flags"],
     tcp["tcp_window"],
     tcp["tcp_chksum"],
     tcp["tcp_urgptr"]) = struct.unpack(">HHLLHHHH", pkt[0:TCP_HDR_LEN])

    tcp["tcp_offset"] = tcp["tcp_flags"] >> 12
    tcp["tcp_flags"] = tcp["tcp_flags"] & 0x1f

    data_offset = tcp["tcp_offset"] * 4
    if data_offset > TCP_HDR_LEN:
        tcp["tcp_options_raw"] = pkt[TCP_HDR_LEN:data_offset]
    tcp["tcp_payload"] = pkt[data_offset:]

    return tcp

def decode_ip(pkt):
    """Decode an IP packet."""
    ip = {}

    (ip["ip_version"],
     ip["ip_dscp"],
     ip["ip_length"],
     ip["ip_id"],
     ip["ip_offset"],
     ip["ip_ttl"],
     ip["ip_protocol"],
     ip["ip_chksum"],
     ip["ip_source"],
     ip["ip_destination"]) = struct.unpack(">BBHHHBBH4s4s", pkt[0:IP_HDR_LEN])

    ip["ip_ihl"] = ip["ip_version"] & 0xf
    ip["ip_version"] = ip["ip_version"] >> 4
    ip["ip_flags"] = ip["ip_offset"] >> 13
    ip["ip_offset"] = ip["ip_offset"] & 0x1fff
    ip["ip_source"] = socket.inet_ntoa(ip["ip_source"])
    ip["ip_destination"] = socket.inet_ntoa(ip["ip_destination"])

    ihl = ip["ip_ihl"] * 4
    if ihl > IP_HDR_LEN:
        ip["ip_options_raw"] = pkt[IP_HDR_LEN:ihl]

    if ip["ip_protocol"] == socket.IPPROTO_ICMP:
        icmp = decode_icmp(pkt[ihl:])
        ip.update(icmp)
    elif ip["ip_protocol"] == socket.IPPROTO_UDP:
        udp = decode_udp(pkt[ihl:])
        ip.update(udp)
    elif ip["ip_protocol"] == socket.IPPROTO_TCP:
        tcp = decode_tcp(pkt[ihl:])
        ip.update(tcp)

    return ip

def decode_ethernet(pkt):
    """Decode an ethernet packet."""
    ether = {}

    ether["ether_dst"], ether["ether_src"], ether["ether_type"] = struct.unpack(
        ">6s6sH", pkt[0:ETHER_HDR_LEN])

    ether["ether_dst"] = printable_ethernet_addr(ether["ether_dst"])
    ether["ether_src"] = printable_ethernet_addr(ether["ether_src"])

    if ether["ether_type"] == ETHERTYPE_IP:
        ether.update(decode_ip(pkt[ETHER_HDR_LEN:]))

    return ether
