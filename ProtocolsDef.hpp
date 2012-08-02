/*
 * AclCheck - simple tool for static analysis of ACLs in network device configuration.
 * Copyright (C) 2012  Tomas Hozza
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <boost/dynamic_bitset.hpp>

#ifndef PROTOCOLS_DEF_HPP__5442511154211631315451313584615878641643808484068164
#define PROTOCOLS_DEF_HPP__5442511154211631315451313584615878641643808484068164

/**
 * Konstantne hodnoty reprezentujuce komunikacny protokol.
 */

const int PROTO_ANY = -2;
const boost::dynamic_bitset< > PROTO_ANY_PREFIX();         /* prefix - "" */

//--------------------------------------------------------------------------------

const int PROTO_IPv4 = -1;
const boost::dynamic_bitset< > PROTO_IPv4_PREFIX(1, 0x00000001);        /* prefix - "1" */

/****************************************************************************************************/
/*** Declarations following http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml ***/
/****************************************************************************************************/

/** IPv6 Hop-by-Hop Option */
const int PROTO_HOPOPT = 0;
const boost::dynamic_bitset< > PROTO_HOPOPT_PREFIX(10, 0x00000001);     /* prefix - "1000 0000 00" */

//--------------------------------------------------------------------------------

/** Internet Control Message */
const int PROTO_ICMPv4 = 1;
const boost::dynamic_bitset< > PROTO_ICMPv4_PREFIX(6, 0x00000003);      /* prefix - "1100 00" */

//--------------------------------------------------------------------------------

/** Internet Group Management */
const int PROTO_IGMP = 2;
const boost::dynamic_bitset< > PROTO_IGMP_PREFIX(6, 0x00000023);        /* prefix - "1100 01" */

//--------------------------------------------------------------------------------

/** Gateway-to-Gateway */
const int PROTO_GGP = 3;
const boost::dynamic_bitset< > PROTO_GGP_PREFIX(10, 0x00000201);        /* prefix - "1000 0000 01" */

//--------------------------------------------------------------------------------

/** IPv4 encapsulation */
const int PROTO_IP_IN_IP = 4;
const boost::dynamic_bitset< > PROTO_IP_IN_IP_PREFIX(6, 0x00000013);    /* prefix - "1100 10" */

//--------------------------------------------------------------------------------

/** Stream */
const int PROTO_ST = 5;
const boost::dynamic_bitset< > PROTO_ST_PREFIX(10, 0x00000101);         /* prefix - "1000 0000 10" */

//--------------------------------------------------------------------------------

/** Transmission Control */
const int PROTO_TCP = 6;
const boost::dynamic_bitset< > PROTO_TCP_PREFIX(4, 0x0000000F);         /* prefix - "1111" */

//--------------------------------------------------------------------------------

/** CBT */
const int PROTO_CBT = 7;
const boost::dynamic_bitset< > PROTO_CBT_PREFIX(10, 0x00000301);        /* prefix - "1000 0000 11" */

//--------------------------------------------------------------------------------

/** Exterior Gateway Protocol */
const int PROTO_EGP = 8;
const boost::dynamic_bitset< > PROTO_EGP_PREFIX(10, 0x00000081);        /* prefix - "1000 0001 00" */

//--------------------------------------------------------------------------------

/** any private interior gateway (used by Cisco for their IGRP) */
const int PROTO_IGP = 9;
const boost::dynamic_bitset< > PROTO_IGP_PREFIX(10, 0x00000281);        /* prefix - "1000 0001 01" */

//--------------------------------------------------------------------------------

/** BBN RCC Monitoring */
const int PROTO_BBN_RCC_MON = 10;
const boost::dynamic_bitset< > PROTO_BBN_RCC_MON_PREFIX(10, 0x00000181);        /* prefix - "1000 0001 10" */

//--------------------------------------------------------------------------------

/** Network Voice Protocol */
const int PROTO_NVP_II = 11;
const boost::dynamic_bitset< > PROTO_NVP_II_PREFIX(10, 0x00000381);     /* prefix - "1000 0001 11" */

//--------------------------------------------------------------------------------

/** PUP */
const int PROTO_PUP = 12;
const boost::dynamic_bitset< > PROTO_PUP_PREFIX(10, 0x00000041);        /* prefix - "1000 0010 00" */

//--------------------------------------------------------------------------------

/** ARGUS */
const int PROTO_ARGUS = 13;
const boost::dynamic_bitset< > PROTO_ARGUS_PREFIX(10, 0x00000241);      /* prefix - "1000 0010 01" */

//--------------------------------------------------------------------------------

/** EMCON */
const int PROTO_EMCON = 14;
const boost::dynamic_bitset< > PROTO_EMCON_PREFIX(10, 0x00000141);      /* prefix - "1000 0010 10" */

//--------------------------------------------------------------------------------

/** Cross Net Debugger */
const int PROTO_XNET = 15;
const boost::dynamic_bitset< > PROTO_XNET_PREFIX(10, 0x00000341);       /* prefix - "1000 0010 11" */

//--------------------------------------------------------------------------------

/** Chaos */
const int PROTO_CHAOS = 16;
const boost::dynamic_bitset< > PROTO_CHAOS_PREFIX(10, 0x000000C1);      /* prefix - "1000 0011 00" */

//--------------------------------------------------------------------------------

/** User Datagram */
const int PROTO_UDP = 17;
const boost::dynamic_bitset<> PROTO_UDP_PREFIX(4, 0x00000007);          /* prefix - "1110" */

//--------------------------------------------------------------------------------

/** Multiplexing */
const int PROTO_MUX = 18;
const boost::dynamic_bitset< > PROTO_MUX_PREFIX(10, 0x000002C1);        /* prefix - "1000 0011 01" */

//--------------------------------------------------------------------------------

/** DCN Measurement Subsystems */
const int PROTO_DCN_MEAS = 19;
const boost::dynamic_bitset< > PROTO_DCN_MEAS_PREFIX(10, 0x000001C1);   /* prefix - "1000 0011 10" */

//--------------------------------------------------------------------------------

/** Host Monitoring */
const int PROTO_HMP = 20;
const boost::dynamic_bitset< > PROTO_HMP_PREFIX(10, 0x000003C1);        /* prefix - "1000 0011 11" */

//--------------------------------------------------------------------------------

/** Packet Radio Measurement */
const int PROTO_PRM = 21;
const boost::dynamic_bitset< > PROTO_PRM_PREFIX(10, 0x00000021);        /* prefix - "1000 0100 00" */

//--------------------------------------------------------------------------------

/** XEROX NS IDP */
const int PROTO_XNS_IDP = 22;
const boost::dynamic_bitset< > PROTO_XNS_IDP_PREFIX(10, 0x00000221);    /* prefix - "1000 0100 01" */

//--------------------------------------------------------------------------------

/** Trunk-1 */
const int PROTO_TRUNK_1 = 23;
const boost::dynamic_bitset< > PROTO_TRUNK_1_PREFIX(10, 0x00000121);    /* prefix - "1000 0100 10" */

//--------------------------------------------------------------------------------

/** Trunk-2 */
const int PROTO_TRUNK_2 = 24;
const boost::dynamic_bitset< > PROTO_TRUNK_2_PREFIX(10, 0x00000321);    /* prefix - "1000 0100 11" */

//--------------------------------------------------------------------------------

/** Leaf-1 */
const int PROTO_LEAF_1 = 25;
const boost::dynamic_bitset< > PROTO_LEAF_1_PREFIX(10, 0x000000A1);     /* prefix - "1000 0101 00" */

//--------------------------------------------------------------------------------

/** Leaf-2 */
const int PROTO_LEAF_2 = 26;
const boost::dynamic_bitset< > PROTO_LEAF_2_PREFIX(10, 0x000002A1);     /* prefix - "1000 0101 01" */

//--------------------------------------------------------------------------------

/** Reliable Data Protocol */
const int PROTO_RDP = 27;
const boost::dynamic_bitset< > PROTO_RDP_PREFIX(10, 0x000001A1);        /* prefix - "1000 0101 10" */

//--------------------------------------------------------------------------------

/** Internet Reliable Transaction */
const int PROTO_IRTP = 28;
const boost::dynamic_bitset< > PROTO_IRTP_PREFIX(10, 0x000003A1);       /* prefix - "1000 0101 11" */

//--------------------------------------------------------------------------------

/** ISO Transport Protocol Class 4 */
const int PROTO_ISO_TP4 = 29;
const boost::dynamic_bitset< > PROTO_ISO_TP4_PREFIX(10, 0x00000061);    /* prefix - "1000 0110 00" */

//--------------------------------------------------------------------------------

/** Bulk Data Transfer Protocol */
const int PROTO_NETBLK = 30;
const boost::dynamic_bitset< > PROTO_NETBLK_PREFIX(10, 0x00000261);     /* prefix - "1000 0110 01" */

//--------------------------------------------------------------------------------

/** MFE Network Services Protocol */
const int PROTO_MFE_NSP = 31;
const boost::dynamic_bitset< > PROTO_MFE_NSP_PREFIX(10, 0x00000161);    /* prefix - "1000 0110 10" */

//--------------------------------------------------------------------------------

/** MERIT Internodal Protocol */
const int PROTO_METRIT_INP = 32;
const boost::dynamic_bitset< > PROTO_METRIT_INP_PREFIX(10, 0x00000361); /* prefix - "1000 0110 11" */

//--------------------------------------------------------------------------------

/** Datagram Congestion Control Protocol */
const int PROTO_DCCP = 33;
const boost::dynamic_bitset< > PROTO_DCCP_PREFIX(10, 0x000000E1);       /* prefix - "1000 0111 00" */

//--------------------------------------------------------------------------------

/** Third Party Connect Protocol */
const int PROTO_3PC = 34;
const boost::dynamic_bitset< > PROTO_3PC_PREFIX(10, 0x000002E1);        /* prefix - "1000 0111 01" */

//--------------------------------------------------------------------------------

/** Inter-Domain Policy Routing Protocol */
const int PROTO_IDPR = 35;
const boost::dynamic_bitset< > PROTO_IDPR_PREFIX(10, 0x000001E1);       /* prefix - "1000 0111 10" */

//--------------------------------------------------------------------------------

/** XTP */
const int PROTO_XTP = 36;
const boost::dynamic_bitset< > PROTO_XTP_PREFIX(10, 0x000003E1);        /* prefix - "1000 0111 11" */

//--------------------------------------------------------------------------------

/** Datagram Delivery Protocol */
const int PROTO_DDP = 37;
const boost::dynamic_bitset< > PROTO_DDP_PREFIX(10, 0x00000011);        /* prefix - "1000 1000 00" */

//--------------------------------------------------------------------------------

/** IDPR Control Message Transport Proto */
const int PROTO_IDPR_CMTP = 38;
const boost::dynamic_bitset< > PROTO_IDPR_CMTP_PREFIX(10, 0x00000211);  /* prefix - "1000 1000 01" */

//--------------------------------------------------------------------------------

/** TP++ Transport Protocol */
const int PROTO_TP_PP = 39;
const boost::dynamic_bitset< > PROTO_TP_PP_PREFIX(10, 0x00000111);      /* prefix - "1000 1000 10" */

//--------------------------------------------------------------------------------

/** IL Transport Protocol */
const int PROTO_IL = 40;
const boost::dynamic_bitset< > PROTO_IL_PREFIX(10, 0x00000311);         /* prefix - "1000 1000 11" */

//--------------------------------------------------------------------------------

/** IPv6 encapsulation */
const int PROTO_IPv4_IPv6 = 41;
const boost::dynamic_bitset< > PROTO_IPv4_IPv6_PREFIX(10, 0x00000091);  /* prefix - "1000 1001 00" */

//--------------------------------------------------------------------------------

/** Source Demand Routing Protocol */
const int PROTO_SDRP = 42;
const boost::dynamic_bitset< > PROTO_SDRP_PREFIX(10, 0x00000291);       /* prefix - "1000 1001 01" */

//--------------------------------------------------------------------------------

/** Routing Header for IPv6 */
const int PROTO_IPv4_IPv6_ROUTE = 43;
const boost::dynamic_bitset< > PROTO_IPv4_IPv6_ROUTE_PREFIX(10, 0x00000191);    /* prefix - "1000 1001 10" */

//--------------------------------------------------------------------------------

/** Fragment Header for IPv6 */
const int PROTO_IPv4_IPv6_FRAG = 44;
const boost::dynamic_bitset< > PROTO_IPv4_IPv6_FRAG_PREFIX(10, 0x00000391);     /* prefix - "1000 1001 11" */

//--------------------------------------------------------------------------------

/** Inter-Domain Routing Protocol */
const int PROTO_IDRP = 45;
const boost::dynamic_bitset< > PROTO_IDRP_PREFIX(10, 0x00000051);       /* prefix - "1000 1010 00" */

//--------------------------------------------------------------------------------

/** Reservation Protocol */
const int PROTO_RSVP = 46;
const boost::dynamic_bitset< > PROTO_RSVP_PREFIX(10, 0x00000251);       /* prefix - "1000 1010 01" */

//--------------------------------------------------------------------------------

/** General Routing Encapsulation */
const int PROTO_GRE = 47;
const boost::dynamic_bitset< > PROTO_GRE_PREFIX(6, 0x00000033);         /* prefix - "1100 11" */

//--------------------------------------------------------------------------------

/** Dynamic Source Routing Protocol */
const int PROTO_DSR = 48;
const boost::dynamic_bitset< > PROTO_DSR_PREFIX(10, 0x00000151);        /* prefix - "1000 1010 10" */

//--------------------------------------------------------------------------------

/** BNA */
const int PROTO_BNA = 49;
const boost::dynamic_bitset< > PROTO_BNA_PREFIX(10, 0x00000351);        /* prefix - "1000 1010 11" */

//--------------------------------------------------------------------------------

/** Encap Security Payload */
const int PROTO_ESP = 50;
const boost::dynamic_bitset< > PROTO_ESP_PREFIX(10, 0x000000D1);        /* prefix - "1000 1011 00" */

//--------------------------------------------------------------------------------

/** Authentication Header */
const int PROTO_AH = 51;
const boost::dynamic_bitset< > PROTO_AH_PREFIX(10, 0x000002D1);         /* prefix - "1000 1011 01" */

//--------------------------------------------------------------------------------

/** Integrated Net Layer Security TUBA */
const int PROTO_I_NLSP = 52;
const boost::dynamic_bitset< > PROTO_I_NLSP_PREFIX(10, 0x000001D1);     /* prefix - "1000 1011 10" */

//--------------------------------------------------------------------------------

/** IP with Encryption */
const int PROTO_SWIPE = 53;
const boost::dynamic_bitset< > PROTO_SWIPE_PREFIX(10, 0x000003D1);      /* prefix - "1000 1011 11" */

//--------------------------------------------------------------------------------

/** NBMA Address Resolution Protocol */
const int PROTO_NARP = 54;
const boost::dynamic_bitset< > PROTO_NARP_PREFIX(10, 0x00000031);       /* prefix - "1000 1100 00" */

//--------------------------------------------------------------------------------

/** IP Mobility */
const int PROTO_MOBILE = 55;
const boost::dynamic_bitset< > PROTO_MOBILE_PREFIX(10, 0x00000231);     /* prefix - "1000 1100 01" */

//--------------------------------------------------------------------------------

/** Transport Layer Security Protocol using Kryptonet key management */
const int PROTO_TLSP = 56;
const boost::dynamic_bitset< > PROTO_TLSP_PREFIX(10, 0x00000131);       /* prefix - "1000 1100 10" */

//--------------------------------------------------------------------------------

/** SKIP */
const int PROTO_SKIP = 57;
const boost::dynamic_bitset< > PROTO_SKIP_PREFIX(10, 0x00000331);       /* prefix - "1000 1100 11" */

//--------------------------------------------------------------------------------

/** ICMP for IPv6 */
const int PROTO_IPv6_ICMP = 58;
const boost::dynamic_bitset< > PROTO_IPv6_ICMP_PREFIX(10, 0x000000B1);  /* prefix - "1000 1101 00" */

//--------------------------------------------------------------------------------

/** No Next Header for IPv6 */
const int PROTO_IPv6_NONXT = 59;
const boost::dynamic_bitset< > PROTO_IPv6_NONXT_PREFIX(10, 0x000002B1); /* prefix - "1000 1101 01" */

//--------------------------------------------------------------------------------

/** Destination Options for IPv6 */
const int PROTO_IPv6_OPTS = 60;
const boost::dynamic_bitset< > PROTO_IPv6_OPTS_PREFIX(10, 0x000001B1);  /* prefix - "1000 1101 10" */

//--------------------------------------------------------------------------------

/** any host internal protocol */
const int PROTO_AHIP = 61;
const boost::dynamic_bitset< > PROTO_AHIP_PREFIX(10, 0x000003B1);       /* prefix - "1000 1101 11" */

//--------------------------------------------------------------------------------

/** CFTP */
const int PROTO_CFTP = 62;
const boost::dynamic_bitset< > PROTO_CFTP_PREFIX(10, 0x00000071);       /* prefix - "1000 1110 00" */

//--------------------------------------------------------------------------------

/** any local network */
const int PROTO_ALN = 63;
const boost::dynamic_bitset< > PROTO_ALN_PREFIX(10, 0x00000271);        /* prefix - "1000 1110 01" */

//--------------------------------------------------------------------------------

/** SATNET and Backroom EXPAK */
const int PROTO_SAT_EXPAK = 64;
const boost::dynamic_bitset< > PROTO_SAT_EXPAK_PREFIX(10, 0x00000171);  /* prefix - "1000 1110 10" */

//--------------------------------------------------------------------------------

/** Kryptolan */
const int PROTO_KRYPTOLAN = 65;
const boost::dynamic_bitset< > PROTO_KRYPTOLAN_PREFIX(10, 0x00000371);  /* prefix - "1000 1110 11" */

//--------------------------------------------------------------------------------

/** MIT Remote Virtual Disk Protocol */
const int PROTO_RVD = 66;
const boost::dynamic_bitset< > PROTO_RVD_PREFIX(10, 0x000000F1);        /* prefix - "1000 1111 00" */

//--------------------------------------------------------------------------------

/** Internet Pluribus Packet Core */
const int PROTO_IPPC = 67;
const boost::dynamic_bitset< > PROTO_IPPC_PREFIX(10, 0x000002F1);       /* prefix - "1000 1111 01" */

//--------------------------------------------------------------------------------

/** any distributed file system */
const int PROTO_ADFS = 68;
const boost::dynamic_bitset< > PROTO_ADFS_PREFIX(10, 0x000001F1);       /* prefix - "1000 1111 10" */

//--------------------------------------------------------------------------------

/** SATNET Monitoring */
const int PROTO_SAT_MON = 69;
const boost::dynamic_bitset< > PROTO_SAT_MON_PREFIX(10, 0x000003F1);    /* prefix - "1000 1111 11" */

//--------------------------------------------------------------------------------

/** VISA Protocol */
const int PROTO_VISA = 70;
const boost::dynamic_bitset< > PROTO_VISA_PREFIX(10, 0x00000009);       /* prefix - "1001 0000 00" */

//--------------------------------------------------------------------------------

/** Internet Packet Core Utility */
const int PROTO_IPCV = 71;
const boost::dynamic_bitset< > PROTO_IPCV_PREFIX(10, 0x00000209);       /* prefix - "1001 0000 01" */

//--------------------------------------------------------------------------------

/** Computer Protocol Network Executive */
const int PROTO_CPNX = 72;
const boost::dynamic_bitset< > PROTO_CPNX_PREFIX(10, 0x00000109);       /* prefix - "1001 0000 10" */

//--------------------------------------------------------------------------------

/** Computer Protocol Heart Beat */
const int PROTO_CPHB = 73;
const boost::dynamic_bitset< > PROTO_CPHB_PREFIX(10, 0x00000309);       /* prefix - "1001 0000 11" */

//--------------------------------------------------------------------------------

/** Wang Span Network */
const int PROTO_WSN = 74;
const boost::dynamic_bitset< > PROTO_WSN_PREFIX(10, 0x00000089);        /* prefix - "1001 0001 00" */

//--------------------------------------------------------------------------------

/** Packet Video Protocol */
const int PROTO_PVP = 75;
const boost::dynamic_bitset< > PROTO_PVP_PREFIX(10, 0x00000289);        /* prefix - "1001 0001 01" */

//--------------------------------------------------------------------------------

/** Backroom SATNET Monitoring */
const int PROTO_BR_SAT_MON = 76;
const boost::dynamic_bitset< > PROTO_BR_SAT_MON_PREFIX(10, 0x00000189); /* prefix - "1001 0001 10" */

//--------------------------------------------------------------------------------

/** SUN ND PROTOCOL-Temporary */
const int PROTO_SUN_ND = 77;
const boost::dynamic_bitset< > PROTO_SUN_ND_PREFIX(10, 0x00000389);     /* prefix - "1001 0001 11" */

//--------------------------------------------------------------------------------

/** WIDEBAND Monitoring */
const int PROTO_WB_MON = 78;
const boost::dynamic_bitset< > PROTO_WB_MON_PREFIX(10, 0x00000049);     /* prefix - "1001 0010 00" */

//--------------------------------------------------------------------------------

/** WIDEBAND EXPAK */
const int PROTO_WB_EXPAK = 79;
const boost::dynamic_bitset< > PROTO_WB_EXPAK_PREFIX(10, 0x00000249);   /* prefix - "1001 0010 01" */

//--------------------------------------------------------------------------------

/** ISO Internet Protocol */
const int PROTO_ISO_IP = 80;
const boost::dynamic_bitset< > PROTO_ISO_IP_PREFIX(10, 0x00000149);     /* prefix - "1001 0010 10" */

//--------------------------------------------------------------------------------

/** VMTP */
const int PROTO_VMTP = 81;
const boost::dynamic_bitset< > PROTO_VMTP_PREFIX(10, 0x00000349);       /* prefix - "1001 0010 11" */

//--------------------------------------------------------------------------------

/** SECURE-VMTP */
const int PROTO_SECURE_VMTP = 82;
const boost::dynamic_bitset< > PROTO_SECURE_VMTP_PREFIX(10, 0x000000C9);        /* prefix - "1001 0011 00" */

//--------------------------------------------------------------------------------

/** VINES */
const int PROTO_VINES = 83;
const boost::dynamic_bitset< > PROTO_VINES_PREFIX(10, 0x000002C9);      /* prefix - "1001 0011 01" */

//--------------------------------------------------------------------------------

/** Protocol Internet Protocol Traffic Manager */
const int PROTO_IPTM = 84;
const boost::dynamic_bitset< > PROTO_IPTM_PREFIX(10, 0x000001C9);       /* prefix - "1001 0011 10" */

//--------------------------------------------------------------------------------

/** NSFNET-IGP */
const int PROTO_NSFNET_IGP = 85;
const boost::dynamic_bitset< > PROTO_NSFNET_IGP_PREFIX(10, 0x000003C9); /* prefix - "1001 0011 11" */

//--------------------------------------------------------------------------------

/** Dissimilar Gateway Protocol */
const int PROTO_DGP = 86;
const boost::dynamic_bitset< > PROTO_DGP_PREFIX(10, 0x00000029);        /* prefix - "1001 0100 00" */

//--------------------------------------------------------------------------------

/** TCF */
const int PROTO_TCF = 87;
const boost::dynamic_bitset< > PROTO_TCF_PREFIX(10, 0x00000229);        /* prefix - "1001 0100 01" */

//--------------------------------------------------------------------------------

/** EIGRP */
const int PROTO_EIGRP = 88;
const boost::dynamic_bitset< > PROTO_EIGRP_PREFIX(6, 0x0000000B);       /* prefix - "1101 00" */

//--------------------------------------------------------------------------------

/** OSPFIGP */
const int PROTO_OSPF = 89;
const boost::dynamic_bitset< > PROTO_OSPF_PREFIX(6, 0x0000002B);        /* prefix - "1101 01" */

//--------------------------------------------------------------------------------

/** Sprite RPC Protocol */
const int PROTO_SPRITE_RPC = 90;
const boost::dynamic_bitset< > PROTO_SPRITE_RPC_PREFIX(10, 0x00000129); /* prefix - "1001 0100 10" */

//--------------------------------------------------------------------------------

/** Locus Address Resolution Protocol */
const int PROTO_LARP = 91;
const boost::dynamic_bitset< > PROTO_LARP_PREFIX(10, 0x00000329);       /* prefix - "1001 0100 11" */

//--------------------------------------------------------------------------------

/** Multicast Transport Protocol */
const int PROTO_MTP = 92;
const boost::dynamic_bitset< > PROTO_MTP_PREFIX(10, 0x000000A9);        /* prefix - "1001 0101 00" */

//--------------------------------------------------------------------------------

/** AX.25 Frames */
const int PROTO_AX_25 = 93;
const boost::dynamic_bitset< > PROTO_AX_25_PREFIX(10, 0x000002A9);      /* prefix - "1001 0101 01" */

//--------------------------------------------------------------------------------

/** IP-within-IP Encapsulation Protocol */
const int PROTO_IPIP = 94;
const boost::dynamic_bitset< > PROTO_IPIP_PREFIX(10, 0x000001A9);       /* prefix - "1001 0101 10" */

//--------------------------------------------------------------------------------

/** Mobile Internetworking Control Pro. */
const int PROTO_MICP = 95;
const boost::dynamic_bitset< > PROTO_MICP_PREFIX(10, 0x000003A9);       /* prefix - "1001 0101 11" */

//--------------------------------------------------------------------------------

/** Semaphore Communications Sec. Pro. */
const int PROTO_SCC_SP = 96;
const boost::dynamic_bitset< > PROTO_SCC_SP_PREFIX(10, 0x00000069);     /* prefix - "1001 0110 00" */

//--------------------------------------------------------------------------------

/** Ethernet-within-IP Encapsulation */
const int PROTO_ETHERIP = 97;
const boost::dynamic_bitset< > PROTO_ETHERIP_PREFIX(10, 0x00000269);    /* prefix - "1001 0110 01" */

//--------------------------------------------------------------------------------

/** Encapsulation Header */
const int PROTO_ENCAP = 98;
const boost::dynamic_bitset< > PROTO_ENCAP_PREFIX(10, 0x00000169);      /* prefix - "1001 0110 10" */

//--------------------------------------------------------------------------------

/** any private encryption scheme */
const int PROTO_APES = 99;
const boost::dynamic_bitset< > PROTO_APES_PREFIX(10, 0x00000369);       /* prefix - "1001 0110 11" */

//--------------------------------------------------------------------------------

/** GMTP */
const int PROTO_GMTP = 100;
const boost::dynamic_bitset< > PROTO_GMTP_PREFIX(10, 0x000000E9);       /* prefix - "1001 0111 00" */

//--------------------------------------------------------------------------------

/** Ipsilon Flow Management Protocol */
const int PROTO_IFMP = 101;
const boost::dynamic_bitset< > PROTO_IFMP_PREFIX(10, 0x000002E9);       /* prefix - "1001 0111 01" */

//--------------------------------------------------------------------------------

/** PNNI over IP */
const int PROTO_PNNI = 102;
const boost::dynamic_bitset< > PROTO_PNNI_PREFIX(10, 0x000001E9);       /* prefix - "1001 0111 10" */

//--------------------------------------------------------------------------------

/** Protocol Independent Multicast */
const int PROTO_PIM = 103;
const boost::dynamic_bitset< > PROTO_PIM_PREFIX(6, 0x0000001B);         /* prefix - "1101 10" */

//--------------------------------------------------------------------------------

/** ARIS */
const int PROTO_ARIS = 104;
const boost::dynamic_bitset< > PROTO_ARIS_PREFIX(10, 0x000003E9);       /* prefix - "1001 0111 11" */

//--------------------------------------------------------------------------------

/** SCPS */
const int PROTO_SCPS = 105;
const boost::dynamic_bitset< > PROTO_SCPS_PREFIX(10, 0x00000019);       /* prefix - "1001 1000 00" */

//--------------------------------------------------------------------------------

/** QNX */
const int PROTO_QNX = 106;
const boost::dynamic_bitset< > PROTO_QNX_PREFIX(10, 0x00000219);        /* prefix - "1001 1000 01" */

//--------------------------------------------------------------------------------

/** Active Networks */
const int PROTO_AN = 107;
const boost::dynamic_bitset< > PROTO_AN_PREFIX(10, 0x00000119);         /* prefix - "1001 1000 10" */

//--------------------------------------------------------------------------------

/** IP Payload Compression Protocol */
const int PROTO_IP_COMP = 108;
const boost::dynamic_bitset< > PROTO_IP_COMP_PREFIX(10, 0x00000319);    /* prefix - "1001 1000 11" */

//--------------------------------------------------------------------------------

/** Sitara Networks Protocol */
const int PROTO_SNP = 109;
const boost::dynamic_bitset< > PROTO_SNP_PREFIX(10, 0x00000099);        /* prefix - "1001 1001 00" */

//--------------------------------------------------------------------------------

/** Compaq Peer Protocol */
const int PROTO_COMPAQ = 110;
const boost::dynamic_bitset< > PROTO_COMPAQ_PREFIX(10, 0x00000299);     /* prefix - "1001 1001 01" */

//--------------------------------------------------------------------------------

/** IPX in IP */
const int PROTO_IPX_IN_IP = 111;
const boost::dynamic_bitset< > PROTO_IPX_IN_IP_PREFIX(10, 0x00000199);  /* prefix - "1001 1001 10" */

//--------------------------------------------------------------------------------

/** Virtual Router Redundancy Protocol */
const int PROTO_VRRP = 112;
const boost::dynamic_bitset< > PROTO_VRRP_PREFIX(10, 0x00000399);       /* prefix - "1001 1001 11" */

//--------------------------------------------------------------------------------

/** PGM Reliable Transport Protocol */
const int PROTO_PGM = 113;
const boost::dynamic_bitset< > PROTO_PGM_PREFIX(10, 0x00000059);        /* prefix - "1001 1010 00" */

//--------------------------------------------------------------------------------

/** any 0-hop protocol */
const int PROTO_AZHP = 114;
const boost::dynamic_bitset< > PROTO_AZHP_PREFIX(10, 0x00000259);       /* prefix - "1001 1010 01" */

//--------------------------------------------------------------------------------

/** Layer Two Tunneling Protocol */
const int PROTO_L2TP = 115;
const boost::dynamic_bitset< > PROTO_L2TP_PREFIX(10, 0x00000159);       /* prefix - "1001 1010 10" */

//--------------------------------------------------------------------------------

/** D-II Data Exchange (DDX) */
const int PROTO_DDX = 116;
const boost::dynamic_bitset< > PROTO_DDX_PREFIX(10, 0x00000359);        /* prefix - "1001 1010 11" */

//--------------------------------------------------------------------------------

/** Interactive Agent Transfer Protocol */
const int PROTO_IATP = 117;
const boost::dynamic_bitset< > PROTO_IATP_PREFIX(10, 0x000000D9);       /* prefix - "1001 1011 00" */

//--------------------------------------------------------------------------------

/** Schedule Transfer Protocol */
const int PROTO_STP = 118;
const boost::dynamic_bitset< > PROTO_STP_PREFIX(10, 0x000002D9);        /* prefix - "1001 1011 01" */

//--------------------------------------------------------------------------------

/** SpectraLink Radio Protocol */
const int PROTO_SRP = 119;
const boost::dynamic_bitset< > PROTO_SRP_PREFIX(10, 0x000001D9);        /* prefix - "1001 1011 10" */

//--------------------------------------------------------------------------------

/** UTI */
const int PROTO_UTI = 120;
const boost::dynamic_bitset< > PROTO_UTI_PREFIX(10, 0x000003D9);        /* prefix - "1001 1011 11" */

//--------------------------------------------------------------------------------

/** Simple Message Protocol */
const int PROTO_SMP = 121;
const boost::dynamic_bitset< > PROTO_SMP_PREFIX(10, 0x00000039);        /* prefix - "1001 1100 00" */

//--------------------------------------------------------------------------------

/** SM */
const int PROTO_SM = 122;
const boost::dynamic_bitset< > PROTO_SM_PREFIX(10, 0x00000239);         /* prefix - "1001 1100 01" */

//--------------------------------------------------------------------------------

/** Performance Transparency Protocol */
const int PROTO_PTP = 123;
const boost::dynamic_bitset< > PROTO_PTP_PREFIX(10, 0x00000139);        /* prefix - "1001 1100 10" */

//--------------------------------------------------------------------------------

/** ISIS over IPv4 */
const int PROTO_IPv4_ISIS = 124;
const boost::dynamic_bitset< > PROTO_IPv4_ISIS_PREFIX(10, 0x00000339);  /* prefix - "1001 1100 11" */

//--------------------------------------------------------------------------------

/** FIRE */
const int PROTO_FIRE = 125;
const boost::dynamic_bitset< > PROTO_FIRE_PREFIX(10, 0x000000B9);       /* prefix - "1001 1101 00" */

//--------------------------------------------------------------------------------

/** Combat Radio Transport Protocol */
const int PROTO_CRTP = 126;
const boost::dynamic_bitset< > PROTO_CRTP_PREFIX(10, 0x000002B9);       /* prefix - "1001 1101 01" */

//--------------------------------------------------------------------------------

/** Combat Radio User Datagram */
const int PROTO_CRUDP = 127;
const boost::dynamic_bitset< > PROTO_CRUDP_PREFIX(10, 0x000001B9);      /* prefix - "1001 1101 10" */

//--------------------------------------------------------------------------------

/** SSCOPMCE */
const int PROTO_SSCOPMCE = 128;
const boost::dynamic_bitset< > PROTO_SSCOPMCE_PREFIX(10, 0x000003B9);   /* prefix - "1001 1101 11" */

//--------------------------------------------------------------------------------

/** IPLT */
const int PROTO_IPLT = 129;
const boost::dynamic_bitset< > PROTO_IPLT_PREFIX(10, 0x00000079);       /* prefix - "1001 1110 00" */

//--------------------------------------------------------------------------------

/** Secure Packet Shield */
const int PROTO_SPS = 130;
const boost::dynamic_bitset< > PROTO_SPS_PREFIX(10, 0x00000279);        /* prefix - "1001 1110 01" */

//--------------------------------------------------------------------------------

/** Private IP Encapsulation within IP */
const int PROTO_PIPE = 131;
const boost::dynamic_bitset< > PROTO_PIPE_PREFIX(10, 0x00000179);       /* prefix - "1001 1110 10" */

//--------------------------------------------------------------------------------

/** Stream Control Transmission Protocol */
const int PROTO_SCTP = 132;
const boost::dynamic_bitset< > PROTO_SCTP_PREFIX(10, 0x00000379);       /* prefix - "1001 1110 11" */

//--------------------------------------------------------------------------------

/** Fibre Channel */
const int PROTO_FC = 133;
const boost::dynamic_bitset< > PROTO_FC_PREFIX(10, 0x000000F9);         /* prefix - "1001 1111 00" */

//--------------------------------------------------------------------------------

/** RSVP-E2E-IGNORE */
const int PROTO_RSVP_E2E_IGNORE = 134;
const boost::dynamic_bitset< > PROTO_RSVP_E2E_IGNORE_PREFIX(10, 0x000002F9);    /* prefix - "1001 1111 01" */

//--------------------------------------------------------------------------------

/** Mobility Header */
const int PROTO_MH = 135;
const boost::dynamic_bitset< > PROTO_MH_PREFIX(10, 0x00001F9);         /* prefix - "1001 1111 10" */

//--------------------------------------------------------------------------------

/** UDPLite */
const int PROTO_UDPL = 136;
const boost::dynamic_bitset< > PROTO_UDPL_PREFIX(10, 0x000003F9);       /* prefix - "1001 1111 11" */

//--------------------------------------------------------------------------------

/** MPLS-in-IP */
const int PROTO_MPLS_IN_IP = 137;
const boost::dynamic_bitset< > PROTO_MPLS_IN_IP_PREFIX(10, 0x00000005); /* prefix - "1010 0000 00" */

//--------------------------------------------------------------------------------

/** MANET Protocols */
const int PROTO_MANET = 138;
const boost::dynamic_bitset< > PROTO_MANET_PREFIX(10, 0x00000205);      /* prefix - "1010 0000 01" */

//--------------------------------------------------------------------------------

/** Host Identity Protocol */
const int PROTO_HIP = 139;
const boost::dynamic_bitset< > PROTO_HIP_PREFIX(10, 0x00000105);        /* prefix - "1010 0000 10" */

//--------------------------------------------------------------------------------

/** Shim6 Protocol */
const int PROTO_SHIM6 = 140;
const boost::dynamic_bitset< > PROTO_SHIM6_PREFIX(10, 0x00000305);      /* prefix - "1010 0000 11" */

//--------------------------------------------------------------------------------

/** Wrapped Encapsulating Security Payload */
const int PROTO_WESP = 141;
const boost::dynamic_bitset< > PROTO_WESP_PREFIX(10, 0x00000085);       /* prefix - "1010 0001 00" */

//--------------------------------------------------------------------------------

/** Robust Header Compression */
const int PROTO_ROHC = 142;
const boost::dynamic_bitset< > PROTO_ROHC_PREFIX(10, 0x00000285);       /* prefix - "1010 0001 01" */

//--------------------------------------------------------------------------------

/** Unassigned or Reserved */
const int PROTO_UNKNOWN = 143;                                          /* protocol number 143 - 255 */
const boost::dynamic_bitset< > PROTO_UNKNOWN_PREFIX(10, 0x000003FD);    /* prefix - "1011 1111 11" */

//--------------------------------------------------------------------------------

/** contstants for check of settings of prootcols and possibility of extensions of adding new protocols */
const int PROTO__MIN = PROTO_ANY;
const int PROTO__MAX = 255;

#endif /* PROTOCOLS_DEF_HPP__5442511154211631315451313584615878641643808484068164 */