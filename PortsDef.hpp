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


#include <sys/types.h>

#ifndef PORTS_DEF_HPP__8748486411084483480113887515387301840413015340744
#define PORTS_DEF_HPP__8748486411084483480113887515387301840413015340744

const u_int16_t PORT_ECHO = 7;                  /** echo */
const u_int16_t PORT_DISCARD = 9;               /** discard */
const u_int16_t PORT_DAYTIME = 13;              /** daytime */
const u_int16_t PORT_CHARGEN = 19;              /** chargen */
const u_int16_t PORT_FTP_DATA = 20;             /** ftp-data */
const u_int16_t PORT_FTP = 21;                  /** ftp */
const u_int16_t PORT_SSH = 22;                  /** ssh */
const u_int16_t PORT_TELNET = 23;               /** telnet */
const u_int16_t PORT_SMTP = 25;                 /** smtp */
const u_int16_t PORT_TIME = 37;                 /** time */
const u_int16_t PORT_NAMESERVER = 42;           /** nameserver */
const u_int16_t PORT_WHOIS = 43;                /** whois */
const u_int16_t PORT_TACACS = 49;               /** tacacs */
const u_int16_t PORT_DOMAIN = 53;               /** domain */
const u_int16_t PORT_TACACS_DS = 65;            /** tacacs-ds */
const u_int16_t PORT_BOOTPS = 67;               /** bootps */
const u_int16_t PORT_BOOTPC = 68;               /** bootpc */
const u_int16_t PORT_TFTP = 69;                 /** tftp */
const u_int16_t PORT_GOPHER = 70;               /** gopher */
const u_int16_t PORT_FINGER = 79;               /** finger */
const u_int16_t PORT_WWW = 80;                  /** www */
const u_int16_t PORT_KERBEROS_SEC = 88;         /** kerberos-sec */
const u_int16_t PORT_HOSTNAME = 101;            /** hostname */
const u_int16_t PORT_POP2 = 109;                /** pop2 */
const u_int16_t PORT_POP3 = 110;                /** pop3 */
const u_int16_t PORT_SUNRPC = 111;              /** sunrpc */
const u_int16_t PORT_IDENT = 113;               /** ident */
const u_int16_t PORT_NNTP = 119;                /** nntp */
const u_int16_t PORT_NTP = 123;                 /** ntp */
const u_int16_t PORT_NETBIOS_NS = 137;          /** netbios-ns */
const u_int16_t PORT_NETBIOS_DGM = 138;         /** netbios-dgm */
const u_int16_t PORT_NETBIOS_SS = 139;          /** netbios-ss */
const u_int16_t PORT_IMAP = 143;                /** imap */
const u_int16_t PORT_SNMP = 161;                /** snmp */
const u_int16_t PORT_SNMPTRAP = 162;            /** snmptrap */
const u_int16_t PORT_XDMCP = 177;               /** xdmcp */
const u_int16_t PORT_BGP = 179;                 /** bgp */
const u_int16_t PORT_IRC = 194;                 /** irc */
const u_int16_t PORT_DNSIX = 195;               /** dnsix */
const u_int16_t PORT_LDAP = 389;                /** ldap */
const u_int16_t PORT_MOBILE_IP = 434;           /** mobile-ip */
const u_int16_t PORT_MOBIL_IP_MN = 435;         /** mobilip-mn */
const u_int16_t PORT_HTTPS = 443;               /** https */
const u_int16_t PORT_SNPP = 444;                /** snpp */
const u_int16_t PORT_PIM_AUTO_RP = 496;         /** pim-auto-rp */
const u_int16_t PORT_ISAKMP = 500;              /** isakmp */
const u_int16_t PORT_BIFF = 512;                /** biff */
const u_int16_t PORT_EXEC = 512;                /** exec */
const u_int16_t PORT_LOGIN = 513;               /** login */
const u_int16_t PORT_WHO = 513;                 /** who */
const u_int16_t PORT_CMD = 514;                 /** cmd */
const u_int16_t PORT_SYSLOG = 514;              /** syslog */
const u_int16_t PORT_LPD = 515;                 /** lpd */
const u_int16_t PORT_TALK = 517;                /** talk */
const u_int16_t PORT_NTALK = 518;               /** ntalk */
const u_int16_t PORT_RIP = 520;                 /** rip */
const u_int16_t PORT_TIMED = 525;               /** timed */
const u_int16_t PORT_UUCP = 540;                /** uucp */
const u_int16_t PORT_KLOGIN = 543;              /** klogin */
const u_int16_t PORT_KSHELL = 544;              /** kshell */
const u_int16_t PORT_DHCP = 547;                /** dhcp */
const u_int16_t PORT_MSDP = 639;                /** msdp */
const u_int16_t PORT_LDP = 646;                 /** ldp */
const u_int16_t PORT_KRB_PROP = 754;            /** krb-prop */
const u_int16_t PORT_KRBUPDATE = 760;           /** krbupdate */
const u_int16_t PORT_KPASSWD = 761;             /** kpasswd */
const u_int16_t PORT_SOCKS = 1080;              /** socks */
const u_int16_t PORT_AFS = 1483;                /** afs */
const u_int16_t PORT_RADIUS_OLD = 1645;         /** radius-old */
const u_int16_t PORT_PPTP = 1723;               /** pptp */
const u_int16_t PORT_RADIUS = 1812;             /** radius */
const u_int16_t PORT_RADACCT = 1813;            /** radacct */
const u_int16_t PORT_ZEPHYR_CLT = 2103;         /** zephyr-clt */
const u_int16_t PORT_ZEPHYR_HM = 2104;          /** zephyr-hm */
const u_int16_t PORT_EKLOGIN = 2105;            /** eklogin */
const u_int16_t PORT_EKSHELL = 2106;            /** ekshell */
const u_int16_t PORT_RKINIT = 2108;             /** rkinit */
const u_int16_t PORT_NFSD = 2049;               /** nfsd */
const u_int16_t PORT_CVSPSERVER = 2401;         /** cvspserver */
const u_int16_t PORT_NON500_ISAKMP = 4500;      /** non500-isakmp */

#endif /* PORTS_DEF_HPP__8748486411084483480113887515387301840413015340744 */