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

#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

#include "CiscoInputParser.hpp"
#include "PortsDef.hpp"

using namespace std;

/**
 * Method for getting pointer to an ACL with entered name (ID).
 *
 * Method returns pointer to an ACL with name (ID) entered as
 * an integer value. If ACL with entered name (ID) doesn't exist
 * method creates new ACL with entered name (ID) and returns the pointer.
 *
 * @param name integer value representing name (ID) of an ACL.
 * @return pointer to ACL with entered name (ID).
 */
AccessControlList* CiscoInputParser::getAclByName(int name)
{
    stringstream ss;
    ss << name;
    string tmp_name = ss.str();
    
    if ( m_aclsByName.count(tmp_name) == 0 )
    {
        return createNewAcl(tmp_name);
    }
    else
    {
        return m_aclsByName[tmp_name];
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for getting pointer to an ACL with entered name (ID).
 *
 * Method returns pointer to an ACL with name (ID) entered as
 * string. If ACL with entered name (ID) doesn't exist method 
 * creates new ACL with entered name (ID) and returns the pointer.
 *
 * @param name string containing name (ID) of an ACL.
 * @return pointer to ACL with entered name (ID).
 */
AccessControlList* CiscoInputParser::getAclByName(const std::string& name)
{
    if ( m_aclsByName.count(name) == 0 )
    {
        return createNewAcl(name);
    }
    else
    {
        return m_aclsByName[name];
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for creating new ACL with entered name.
 *
 * Method creates new ACL witch entered name and returns 
 * pointer to it. Method adds new ACL to the vector containing
 * all parsed ACLs and to the map (used for accessing ACLs by name)
 * under its name.
 *
 * @param name string containing name of new ACL.
 * @return pointer to the new ACL.
 */
AccessControlList* CiscoInputParser::createNewAcl(const std::string& name)
{
    AccessControlList* accessList = new AccessControlList(name);

    m_aclsVector->push_back(accessList);
    m_aclsByName[name] = accessList;

    return accessList;
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing type of command from passed string.
 *
 * Method parses type of command from passed string. String has
 * to begin with the command! Method also stores to variable charsExtracted
 * number of characters extracted by parsing the command.
 *
 * @param str pointer to string beginning with a command.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return CMD_ACCESS_LIST - string begins with command "access-list".
 *         CMD_IP_ACCESS_LIST - string begins with command "ip access-list".
 *         CMD_IP_ACCESS_LIST_RULE - string begins with command "permit" or "deny".
 *         CMD_ACL_RULE_REMARK - string begins with command "remark".
 *         CMD_MISC - string begins with some other command or special symbol.
 */
int CiscoInputParser::parseCommand(const char* str, unsigned& charsExtracted)
{
    switch ( str[0] )
    {
        case 'a':
            if ( strncmp(str, "access-list", 11) == 0 )
            {
                charsExtracted = 12;
                return CMD_ACCESS_LIST;
            }

        case 'i':
            if ( strncmp(str, "ip access-list", 14) == 0 )
            {
                charsExtracted = 15;
                return CMD_IP_ACCESS_LIST;
            }

        case 'p':
        case 'd':
            if ( (strncmp(str, "permit", 6) == 0) || (strncmp(str, "deny", 4) == 0) )
            {
                charsExtracted = 1;
                return CMD_IP_ACCESS_LIST_RULE;
            }

        case 'r':
            if ( strncmp(str, "remark", 6) == 0 )
            {
                charsExtracted = 7;
                return CMD_ACL_RULE_REMARK;
            }

        default:
            return CMD_MISC;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing type of rule action from passed string.
 *
 * Method parses type of rule action from passed string. String has
 * to begin with the action command! Method also stores to variable 
 * charsExtracted number of characters extracted by parsing the command.
 *
 * @param str pointer to string beginning with a rule action command.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return ACTION_ALLOW - string begins with action "permit".
 *         ACTION_DENY - string begins with action "deny".
 *         CMD_ACL_RULE_REMARK - string begins with command "remark".
 */
int CiscoInputParser::parseAction(const char* str, unsigned& charsExtracted)
{
    if ( strncmp(str, "permit", 6) == 0 )
    {
        charsExtracted = 7;
        return ACTION_ALLOW;
    }
    else if ( strncmp(str, "deny", 4) == 0 )
    {
        charsExtracted = 5;
        return ACTION_DENY;
    }
    else
    {
        charsExtracted = 7;
        return CMD_ACL_RULE_REMARK;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing protocol from passed string.
 *
 * Method parses communication protocol from passed string. String has
 * to begin with the protocol! Method also stores to variable 
 * charsExtracted number of characters extracted by parsing the protocol.
 *
 * @param str pointer to string beginning with a protocol.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return PROTO_XXX - value representing known protocol.
 *         Value representing unknown/unregistered communication protocol (max. value is 255).
 */
int CiscoInputParser::parseProtocol(const char* str, unsigned& charsExtracted)
{
    switch ( str[0] )
    {
        case 'a':
            /* protocol "ahp" */
            charsExtracted = 4;
            return PROTO_AH;

        case 'g':
            /*  protocol "gre" */
            charsExtracted = 4;
            return PROTO_GRE;

        case 'n':
            /* protocol "nos" - old name for protocol number "4" */
            charsExtracted = 4;
            return PROTO_IP_IN_IP;

        case 'o':
            /* protocol "ospf" */
            charsExtracted = 5;
            return PROTO_OSPF;

        case 'p':
            /* protocol "pim" */
            charsExtracted = 4;
            return PROTO_PIM;

        case 't':
            /* protocol "tcp" */
            charsExtracted = 4;
            return PROTO_TCP;

        case 'u':
            /* protocol "udp" */
            charsExtracted = 4;
            return PROTO_UDP;

        case 'e':
            /* protocols "esp" and "eigrp" */
            switch ( str[1] )
            {
                case 's':
                    /* protocol "esp" */
                    charsExtracted = 4;
                    return PROTO_ESP;

                default:
                    /* protocol "eigrp" */
                    charsExtracted = 6;
                    return PROTO_EIGRP;
            }

        case 'i':
            /* protocols "icmp", "igmp", "ipinip" and "ip" */
            switch ( str[1] )
            {
                case 'c':
                    /* protocol "icmp" */
                    charsExtracted = 5;
                    return PROTO_ICMPv4;

                case 'g':
                    /* protocol "igmp" */
                    charsExtracted = 5;
                    return PROTO_IGMP;

                default:
                    /* protocols "ipinip" and "ip" */
                    switch ( str [2])
                    {
                        case 'i':
                            /* protocol "ipinip" */
                            charsExtracted = 7;
                            return PROTO_IP_IN_IP;

                        default:
                            /* protocol "ip" */
                            charsExtracted = 3;
                            return PROTO_IPv4;
                    }
            }

        default:
            return parseProtocolByNum(str, charsExtracted);
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing protocol number from passed string.
 *
 * Method parses communication protocol number from passed string.
 * String has to begin with the protocol number! Method also stores
 * to variable charsExtracted number of characters extracted by 
 * parsing the protocol number.
 *
 * @param str pointer to string beginning with a protocol number.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return value representing communication protocol (value from 0 to 255).
 */
int CiscoInputParser::parseProtocolByNum(const char* str, unsigned& charsExtracted)
{
    char buffer[8];
    stringstream ss;
    ss.str(str);
    ss.getline(buffer, 8, ' ');

    charsExtracted = (unsigned) ss.gcount();

    return atoi(buffer);
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing start and end port number of port range from passed string.
 * 
 * Method parses start and end port number of a port range from passed string.
 * String has to begin with the port range! Method also stores to variable
 * charsExtracted number of characters extracted by parsing the port numbers.
 *
 * @param str pointer to string beginning with a definition of port range.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @param portStart reference to variable where the start port number will be stored.
 * @param portStop reference to variable where the end port number will be stored.
 * @param portNeg reference to variable where the flag of negated/inverted port range will be stored.
 * @return 0 - There was NO port range definition in passed string.
 *         1 - There was a port range definition in passed string.
 */
int CiscoInputParser::parsePort(const char* str, unsigned& charsExtracted, u_int16_t& portStart, u_int16_t& portStop, bool& portNeg)
{
    u_int16_t tmp_portNumber;
    unsigned tmp_chExtr = 0;
    
    
    switch ( str[0] )
    {
        /* "lt" - less than */
        case 'l':
            charsExtracted = 3;
            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;
            
            portStart = 0x0000;
            ( tmp_portNumber == 0 ) ? portStop = 0x0000 : portStop = tmp_portNumber - 1;
            portNeg = false;

            return 1;

        /* "gt" - greather than */
        case 'g':
            charsExtracted = 3;
            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;

            ( tmp_portNumber == 0xFFFF ) ? portStart = 0xFFFF : portStart = tmp_portNumber + 1;
            portStop = 0xFFFF;
            portNeg = false;
            
            return 1;

        /* "eq" - equal */
        case 'e':
            charsExtracted = 3;
            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;

            portStart = portStop = tmp_portNumber;
            portNeg = false;
            
            return 1;

        /* "neq" - not equal */
        case 'n':
            charsExtracted = 4;
            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;

            portStart = portStop = tmp_portNumber;
            portNeg = true;
            
            return 1;

        /* "range" - range */
        case 'r':
            charsExtracted = 6;
            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;
            
            portStart = tmp_portNumber;

            ( isdigit(*(str + charsExtracted)) ) ? tmp_portNumber = parsePortByNum(str + charsExtracted, tmp_chExtr) : tmp_portNumber = parsePortByName(str + charsExtracted, tmp_chExtr);
            charsExtracted += tmp_chExtr;

            portStop = tmp_portNumber;
            
            portNeg = false;

            return 1;

        default:
            charsExtracted = 0;
            return 0;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing port number from passed string.
 * 
 * Method parses port number from passed string. 
 * String has to begin with the port number! Method also stores
 * to variable charsExtracted number of characters extracted by parsing
 * the port number.
 *
 * @param str pointer to string beginning with a port number.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return value representing port number.
 */
u_int16_t CiscoInputParser::parsePortByNum(const char* str, unsigned& charsExtracted)
{
    char buffer[8];
    stringstream ss;
    ss.str(str);
    ss.getline(buffer, 8, ' ');

    charsExtracted = (unsigned) ss.gcount();

    return (u_int16_t)atoi(buffer);
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing port number from port name contained in passed string.
 * 
 * Method parses port number from port name contained in passed string. 
 * String has to begin with the port name! Method also stores
 * to variable charsExtracted number of characters extracted by parsing
 * the port number.
 *
 * @param str pointer to string beginning with a port name.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return value representing port name.
 */
u_int16_t CiscoInputParser::parsePortByName(const char* str, unsigned& charsExtracted)
{
    switch ( str[0] )
    {
        case 'b':
            if ( strncmp(str, "bgp", 3) == 0 )
            {
                charsExtracted = 4;
                return PORT_BGP;
            }
            else if ( strncmp(str, "biff", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_BIFF;
            }
            else if ( strncmp(str, "bootpc", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_BOOTPC;
            }
            /* bootps */
            else
            {
                charsExtracted = 7;
                return PORT_BOOTPS;
            }

        case 'c':
            if ( strncmp(str, "chargen", 7) == 0 )
            {
                charsExtracted = 8;
                return PORT_CHARGEN;
            }
            else if ( strncmp(str, "comsat", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_BIFF;       /* port # same as comsat */
            }
            /* cmd */
            else
            {
                charsExtracted = 4;
                return PORT_CMD;
            }

        case 'd':
            if ( strncmp(str, "daytime", 7) == 0 )
            {
                charsExtracted = 8;
                return PORT_DAYTIME;
            }
            else if ( strncmp(str, "discard", 7) == 0 )
            {
                charsExtracted = 8;
                return PORT_DISCARD;
            }
            else if ( strncmp(str, "dnsix", 5) == 0 )
            {
                charsExtracted = 6;
                return PORT_DNSIX;
            }
            /* domain */
            else
            {
                charsExtracted = 7;
                return PORT_DOMAIN;
            }

        case 'e':
            if ( strncmp(str, "echo", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_ECHO;
            }
            /* exec */
            else
            {
                charsExtracted = 5;
                return PORT_EXEC;
            }

        case 'f':
            if ( strncmp(str, "finger", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_FINGER;
            }
            else if ( strncmp(str, "ftp", 3) == 0 )
            {
                charsExtracted = 4;
                return PORT_FTP;
            }
            /* ftp-data */
            else
            {
                charsExtracted = 9;
                return PORT_FTP_DATA;
            }

        case 'g':
            /* gopher */
            charsExtracted = 7;
            return PORT_GOPHER;

        case 'h':
            if ( strncmp(str, "http", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_WWW;
            }
            /* hostname */
            else
            {
                charsExtracted = 9;
                return PORT_HOSTNAME;
            }

        case 'i':
            if ( strncmp(str, "ident", 5) == 0 )
            {
                charsExtracted = 6;
                return PORT_IDENT;
            }
            else if ( strncmp(str, "irc", 3) == 0)
            {
                charsExtracted = 4;
                return PORT_IRC;
            }
            /* isakmp */
            else
            {
                charsExtracted = 7;
                return PORT_ISAKMP;
            }

        case 'k':
            if ( strncmp(str, "klogin", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_KLOGIN;
            }
            /* kshell */
            else
            {
                charsExtracted = 7;
                return PORT_KSHELL;
            }

        case 'l':
            if ( strncmp(str, "login", 5) == 0 )
            {
                charsExtracted = 6;
                return PORT_LOGIN;
            }
            /* lpd */
            else
            {
                charsExtracted = 4;
                return PORT_LPD;
            }

        case 'm':
            /* mobile-ip */
            charsExtracted = 10;
            return PORT_MOBILE_IP;

        case 'n':
            if ( strncmp(str, "nameserver", 10) == 0 )
            {
                charsExtracted = 11;
                return PORT_NAMESERVER;
            }
            else if ( strncmp(str, "netbios-dgm", 11) == 0 )
            {
                charsExtracted = 12;
                return PORT_NETBIOS_DGM;
            }
            else if ( strncmp(str, "netbios-ns", 10) == 0 )
            {
                charsExtracted = 11;
                return PORT_NETBIOS_NS;
            }
            else if ( strncmp(str, "netbios-ss", 10) == 0 )
            {
                charsExtracted = 11;
                return PORT_NETBIOS_SS;
            }
            else if ( strncmp(str, "nntp", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_NNTP;
            }
            else if ( strncmp(str, "non500-isakmp", 13) == 0 )
            {
                charsExtracted = 14;
                return PORT_NON500_ISAKMP;
            }
            /* ntp */
            else
            {
                charsExtracted = 4;
                return PORT_NTP;
            }

        case 'p':
            if ( strncmp(str, "pim-auto-rp", 11) == 0 )
            {
                charsExtracted = 12;
                return PORT_PIM_AUTO_RP;
            }
            else if ( strncmp(str, "pop2", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_POP2;
            }
            /* pop3 */
            else
            {
                charsExtracted = 5;
                return PORT_POP3;
            }

        case 'r':
            if ( strncmp(str, "rwho", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_WHO;
            }
            else if ( strncmp(str, "router", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_RIP;
            }
            /* rip */
            else
            {
                charsExtracted = 4;
                return PORT_RIP;
            }

        case 's':
            if ( strncmp(str, "smtp", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_SMTP;
            }
            else if ( strncmp(str, "snmp", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_SNMP;
            }
            else if ( strncmp(str, "snmptrap", 8) == 0 )
            {
                charsExtracted = 9;
                return PORT_SNMPTRAP;
            }
            else if ( strncmp(str, "sunrpc", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_SUNRPC;
            }
            /* syslog */
            else
            {
                charsExtracted = 7;
                return PORT_SYSLOG;
            }

        case 't':
            if ( strncmp(str, "tacacs", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_TACACS;
            }
            else if ( strncmp(str, "talk", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_TALK;
            }
            else if ( strncmp(str, "telnet", 6) == 0 )
            {
                charsExtracted = 7;
                return PORT_TELNET;
            }
            else if ( strncmp(str, "tftp", 4) == 0 )
            {
                charsExtracted = 5;
                return PORT_TFTP;
            }
            /* time */
            else
            {
                charsExtracted = 5;
                return PORT_TIME;
            }

        case 'u':
            /* uucp */
            charsExtracted = 5;
            return PORT_UUCP;

        case 'w':
            if ( strncmp(str, "who", 3) == 0 )
            {
                charsExtracted = 4;
                return PORT_WHO;
            }
            else if ( strncmp(str, "whois", 5) == 0 )
            {
                charsExtracted = 6;
                return PORT_WHOIS;
            }
            /* www */
            else
            {
                charsExtracted = 4;
                return PORT_WWW;
            }

        /* xdmcp */
        default:
            charsExtracted = 6;
            return PORT_XDMCP;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for processing rule of unnamed ACL.
 *
 * Method process rule of unnamed ACL and returns smart pointer
 * to the object containing the processed rule. The passed string
 * has to begin with rule definition.
 *
 * @param number number of unnamed ACL of which is the rule a part.
 * @param position position ot rule we are processing in ACL.
 * @param str pointer to string containing definition of the rule.
 * @return smart pointer containing pointer to the new rule object.
 */
auto_ptr< AclRule > CiscoInputParser::handleAccessList(int number, unsigned position, const char* str)
{
    /* determine ACL type */
    if ( resolveAccessListType(number) == ACL_STANDARD )
    {
        return handleStandardRule(position, str);
    }
    else
    {
        return handleExtendedRule(position, str);
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for processing rule of standard ACL.
 *
 * Method process rule of a standard ACL and returns smart pointer
 * to the processed rule object. Passed string has to begin with 
 * rule definition.
 *
 * @param position position of the rule in ACL.
 * @param str pointer to string containing definition of a standard rule.
 * @return smart pointer to new rule object.
 */
auto_ptr< AclRule > CiscoInputParser::handleStandardRule(unsigned position, const char* str)
{
    auto_ptr< AclRule > tmp_rule(new AclRule(position));
    AclRule& rule = *tmp_rule;
    const char* tmp_buffer = str;
    unsigned chExtracted = 0;

    int action = parseAction(tmp_buffer, chExtracted);
    rule.setAction(action);
    tmp_buffer += chExtracted;                  /* move after the action definition */
    skipWhiteChars(tmp_buffer, chExtracted);
    tmp_buffer += chExtracted;

    IP_ADDRESS tmp_addr, tmp_wildC;
    IP_ADDRESS tmp_addrStart, tmp_addrStop;
    unsigned temp;

    parseAddrAndWildcard(tmp_buffer, tmp_addr, tmp_wildC, temp);
    fillIPv4Range(tmp_addr, tmp_wildC, tmp_addrStart, tmp_addrStop);
    rule.setSrcIP(tmp_addrStart, tmp_addrStop);
    
    return tmp_rule;
}

//--------------------------------------------------------------------------------

/**
 * Method for processing rule of extended ACL.
 *
 * Method process rule of an extended ACL and returns smart pointer
 * to the processed rule object. Passed string has to begin with 
 * rule definition.
 *
 * @param position position of the rule in ACL.
 * @param str pointer to string containing definition of an extended rule.
 * @return smart pointer to new rule object.
 */
auto_ptr< AclRule > CiscoInputParser::handleExtendedRule(unsigned position, const char* str)
{
    auto_ptr< AclRule > tmp_rule(new AclRule(position));
    AclRule& rule = *tmp_rule;
    const char* tmp_buffer = str;
    unsigned chExtracted = 0;
    int tmp_protocol;
    int tmp_action;
    IP_ADDRESS tmp_ipAddr;
    IP_ADDRESS tmp_wildC;
    IP_ADDRESS tmp_rangeStart;
    IP_ADDRESS tmp_rangeStop;
    u_int16_t tmp_portStart;
    u_int16_t tmp_portStop;
    bool tmp_portNeg;

    /********** ACTION **********/
    /* searching for first occurance of some action */
    const char* tmp_chPtr = strstr(tmp_buffer, "deny");
    if ( tmp_chPtr == NULL )
    {
        tmp_chPtr = strstr(tmp_buffer, "permit");
    }
    
    tmp_buffer = tmp_chPtr;

    tmp_action = parseAction(tmp_buffer, chExtracted);
    rule.setAction(tmp_action);

    /********** PROTOCOL **********/
    tmp_buffer += chExtracted;
    skipWhiteChars(tmp_buffer, chExtracted);
    tmp_buffer += chExtracted;
    
    tmp_protocol = parseProtocol(tmp_buffer, chExtracted);
    rule.setProtocol(tmp_protocol);

    /********** SOURCE IP **********/
    tmp_buffer += chExtracted;
    skipWhiteChars(tmp_buffer, chExtracted);
    tmp_buffer += chExtracted;
    parseAddrAndWildcard(tmp_buffer, tmp_ipAddr, tmp_wildC, chExtracted);       /* extract address and wildcard */
    fillIPv4Range(tmp_ipAddr, tmp_wildC, tmp_rangeStart, tmp_rangeStop);        /* transformation to address range */
    rule.setSrcIP(tmp_rangeStart, tmp_rangeStop);

    /********** SOURCE PORT **********/
    if ( (tmp_protocol == PROTO_TCP) || (tmp_protocol == PROTO_UDP) )
    {
        tmp_buffer += chExtracted;
        skipWhiteChars(tmp_buffer, chExtracted);
        tmp_buffer += chExtracted;

        /* if there is a port definition after IP address */
        if ( parsePort(tmp_buffer, chExtracted, tmp_portStart, tmp_portStop, tmp_portNeg) == 1 )
        {
            rule.setSrcPort(tmp_portStart, tmp_portStop, tmp_portNeg);
        }
    }

    /********** DESTINATION IP **********/
    tmp_buffer += chExtracted;
    skipWhiteChars(tmp_buffer, chExtracted);
    tmp_buffer += chExtracted;
    
    parseAddrAndWildcard(tmp_buffer, tmp_ipAddr, tmp_wildC, chExtracted);       /* extract address and wildcard */
    fillIPv4Range(tmp_ipAddr, tmp_wildC, tmp_rangeStart, tmp_rangeStop);        /* transformation to address range */
    rule.setDstIP(tmp_rangeStart, tmp_rangeStop);

    /********** DESTINATION PORT **********/
    if ( (tmp_protocol == PROTO_TCP) || (tmp_protocol == PROTO_UDP) )
    {
        tmp_buffer += chExtracted;
        skipWhiteChars(tmp_buffer, chExtracted);
        tmp_buffer += chExtracted;

        /* if there is a port definition after IP address */
        if ( parsePort(tmp_buffer, chExtracted, tmp_portStart, tmp_portStop, tmp_portNeg) == 1 )
        {
            rule.setDstPort(tmp_portStart, tmp_portStop, tmp_portNeg);
        }
    }
    
    return tmp_rule;
}


//--------------------------------------------------------------------------------

/**
 * Method for determining ACL type based on its number.
 *
 * Method determines ACL type based on its number
 * (if its standard or extended.
 *
 * @param number number of the ACL.
 * @return ACL_STANDARD - it is a stndard ACL.
 *         ACL_EXTENDED - it is an extended ACL.
 *         ERROR_FLAG - if the passed number is not standard nor extended ACL number.
 */
int CiscoInputParser::resolveAccessListType(int number)
{
    if ( ((number >= 1) && (number <= 99)) || ((number >= 1300) && (number <= 1999)) )
    {
        return ACL_STANDARD;
    }
    else if ( ((number >= 100) && (number <= 199)) || ((number >= 2000) && (number <= 2699)) )
    {
        return ACL_EXTENDED;
    }
    else
    {
        return ERROR_FLAG;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method resolves ACL type based on named ACL definition.
 *
 * Method resolves ACL type based on string containing
 * its definition.
 *
 * @param str string containing type of named ACL.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return ACL_STANDARD - it is a stndard ACL.
 *         ACL_EXTENDED - it is an extended ACL.
 *         ERROR_FLAG - if the passed number is not standard nor extended ACL number.
 */
int CiscoInputParser::resolveAccessListType(const char* str, unsigned& charsExtracted)
{
    
    if ( strncmp(str, "standard", 8) == 0 )
    {
        charsExtracted = 9;
        return ACL_STANDARD;
    }
    else if ( strncmp(str, "extended", 8) == 0 )
    {
        charsExtracted = 9;
        return ACL_EXTENDED;
    }
    else
    {
        return ERROR_FLAG;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method for parsing unnamed ACL number from string.
 *
 * Method parses unnamed ACL number from passed string
 * and stores number of extracted characters in appropriate
 * variable.
 *
 * @param str pointer to string containing number of unnamed ACL.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 * @return parsed number of unnamed ACL.
 */
int CiscoInputParser::parseAccessListNumber(const char* str, unsigned& charsExtracted)
{
    char buffer[8];
    stringstream ss;

    ss.str(str);
    ss.getline(buffer, 8, ' ');
    charsExtracted = ss.gcount();
    int number = atoi(buffer);

    return number;
}

//--------------------------------------------------------------------------------

/**
 * Method returns the object std::string containing the name of passed ACL.
 *
 * Method returns the object std::string containing the name of the passed ACL's string of characters.
 *
 * @param str pointer to string of characters containing the name of the ACL.
 * @return object std::string containing the name of ACL.
 */
string CiscoInputParser::parseAccessListName(const char* str)
{
    int i = 0;
    while ( !isspace(str[i]) && (str[i] != '\0') )
    {
        i++;
    }

    return string(str, i);
}

//--------------------------------------------------------------------------------

/**
 * Method parses IP address and wildcard from passed string.
 *
 * Method also sets the number of characters extracted from passed string to variable charsExtracted.
 *
 * @param str pointer to string cntaining IP address and wildcard.
 * @param addr reference to structure IP_ADDRESS where the parsed IP address will be stored.
 * @param wildC reference to structure IP_ADDRESS where the parsed wildcard will be stored.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 */
void CiscoInputParser::parseAddrAndWildcard(const char* str, IP_ADDRESS& addr, IP_ADDRESS& wildC, unsigned& charsExtracted)
{
    switch ( str[0] )
    {
        /* address contains "any" */
        case 'a':
        {
            *((u_int32_t*)&addr) = 0x00000000;
            *((u_int32_t*)&wildC) = 0xFFFFFFFF;
            charsExtracted = 3;
            return;
        }

        /* address contains "host" */
        case 'h':
        {
            char tmp[16];
            stringstream ss;
            ss.str(str + 5);                    /* shift after "host " */
            
            ss.getline(tmp, 16, ' ');           /* get IP address */
            charsExtracted = ss.gcount();       /* number of characters extracted by last getline() */
            charsExtracted += 5;                /* add one more "host " */
            addr = parseIPv4addr(tmp);          /* parse IP address */
            *((u_int32_t*)&wildC) = 0x00000000;
            return;
        }

        /* address contains "addr a wildCard" */
        default:
        {
            char tmp[16];
            stringstream ss;
            ss.str(str);
            ss.getline(tmp, 16, ' ');           /* get IP address */
            charsExtracted = ss.gcount();       /* number of characters extracted by last getline() */
            addr = parseIPv4addr(tmp);

            unsigned tmpCount = 0;
            skipWhiteChars(str + charsExtracted, tmpCount);
            charsExtracted += tmpCount;
            ss.ignore(tmpCount);

            if ( !ss.eof() )
            {
                ss.getline(tmp, 16, ' ');           /* get wildcard */
                charsExtracted += ss.gcount();      /* number of characters extracted by last getline() */
                wildC = parseIPv4addr(tmp);
            }
            else
            {
                *((u_int32_t*)&wildC) = 0x00000000;
            }
            
            return;
        }
    }
}

//--------------------------------------------------------------------------------

/**
 * Method parses IPv4 address from passed string.
 *
 * Method parses IPv4, network mask or wildcard from passed string.
 *
 * @param str pointer to string containing IP address.
 * @return structure IP_ADDRESS containing parsed IP address.
 */
IP_ADDRESS CiscoInputParser::parseIPv4addr(const char* str)
{
    IP_ADDRESS address;

    char tmp[4];
    stringstream ss;
    ss.str(str);

    ss.getline(tmp, 4, '.');
    address.A = atoi(tmp);
    ss.getline(tmp, 4, '.');
    address.B = atoi(tmp);
    ss.getline(tmp, 4, '.');
    address.C = atoi(tmp);
    ss.getline(tmp, 4, '.');
    address.D = atoi(tmp);
    
    return address;
}

//--------------------------------------------------------------------------------

/**
 * Method converts passed wildcard to network mask.
 *
 * @param wildcard reference to the object IP_ADDRESS containing wildcard.
 * @return object IP_ADDRESS containing network mask converted from passed wildcard.
 */
IP_ADDRESS CiscoInputParser::ipV4WildcardToMask(const IP_ADDRESS& wildcard)
{
    IP_ADDRESS mask;

    *((u_int32_t*)&mask) = ~(*((u_int32_t*)&wildcard));
    
    return mask;
}

//--------------------------------------------------------------------------------

/**
 * Method computes start and end IP address of corresponding range from passed IP address and wildcard.
 *
 * @param addr reference to structure IP_ADDRESS containing IP address.
 * @param wildc reference to structure IP_ADDRESS containing wildcard.
 * @param range_start reference to structure IP_ADDRESS where the start IP address of the range will be stored.
 * @param range_stop reference to structure IP_ADDRESS where end IP address of the range will be stored.
 */
void CiscoInputParser::fillIPv4Range(const IP_ADDRESS& addr, const IP_ADDRESS& wildc, IP_ADDRESS& range_start, IP_ADDRESS& range_stop)
{
    *((u_int32_t*)&range_start) = *((u_int32_t*)&addr) & ~(*((u_int32_t*)&wildc));
    *((u_int32_t*)&range_stop) = *((u_int32_t*)&range_start) | *((u_int32_t*)&wildc);
}

//--------------------------------------------------------------------------------

/**
 * Method skips all white characters in passed string.
 *
 * @param str pointer to string whose all white characters till first alphanumerical will be skipped.
 * @param charsExtracted reference to variable where the number of extracted characters will be stored.
 */
void CiscoInputParser::skipWhiteChars(const char* str, unsigned& charsExtracted)
{
    unsigned whiteCh = 0;

    while ( isspace(str[whiteCh]) && (str[whiteCh] != '\0') )
    {
        whiteCh++;
    }

    charsExtracted = whiteCh;
}

//--------------------------------------------------------------------------------

/**
 * Method rolls back in passed std::istream-e by passed number of read characters.
 *
 * @param stream reference to stream which will be rolled back.
 * @param size the value representing number of characters we want to roll back.
 */
void CiscoInputParser::rollbackStream(std::istream& stream, std::streamsize size)
{
    for ( streamsize i = 0; i < size; ++i )
    {
        stream.unget();
    }
}

//--------------------------------------------------------------------------------

/**
 * Method converts the command passed in format of numerical value to string.
 *
 * @param cmd the value representing the command which will be converted to string.
 * @return the string representing the command of passed numerical value.
 */
string CiscoInputParser::commandToString(int cmd)
{
    switch ( cmd )
    {
        case CMD_ACCESS_LIST:
            return "access-list";

        case CMD_IP_ACCESS_LIST:
            return "ip_access-list";

        case CMD_IP_ACCESS_LIST_RULE:
            return "ip_access-list_rule";

        case CMD_MISC:
            return "other_command";

        default:
            return "unknown command!";
    }
}

//--------------------------------------------------------------------------------

/**
 * Method parses passed input stream and returns the vector of parsed ACL with corresponding rules.
 *
 * @param inputStream reference to input stream std::istream containing input configuration.
 * @return smart pointer containing the pointer to the vector of ACL with rules.
 */
auto_ptr< boost::ptr_vector< AccessControlList > > CiscoInputParser::parse(std::istream& inputStream)
{
    /* use smart pointer to store address and control allocated memory */
    m_aclsVector = auto_ptr< boost::ptr_vector< AccessControlList > >(new boost::ptr_vector< AccessControlList >);

    char buffer[256];

    /* read whole input till EOF */
    while ( !inputStream.eof() )
    {
        inputStream.getline(buffer, 256);
        unsigned tmp_extracted = 0;

        char* tmp_buffer = buffer;

        /* skip white characters at the beginning */
        if ( isspace(buffer[0]) )
        {
            skipWhiteChars(buffer, tmp_extracted);
            tmp_buffer += tmp_extracted;
        }

        /* find out the type of command in line */
        int cmd = parseCommand(tmp_buffer, tmp_extracted);

        /*************************/
        /* command "access-list" */
        if ( cmd == CMD_ACCESS_LIST )
        {
            tmp_buffer += tmp_extracted;        /* shift after "access-list " to first character after it */

            skipWhiteChars(tmp_buffer, tmp_extracted);
            tmp_buffer += tmp_extracted;

            int aclNum = parseAccessListNumber(tmp_buffer, tmp_extracted);
            tmp_buffer += tmp_extracted;        /* shift after the number of ACL to the first next character */

            skipWhiteChars(tmp_buffer, tmp_extracted);
            tmp_buffer += tmp_extracted;

            /* skip REMARK command */
            if ( parseAction(tmp_buffer, tmp_extracted) == CMD_ACL_RULE_REMARK )
            {
                continue;
            }
            
            /* get ACL to add new rule */
            AccessControlList* tmp_curentAcl = getAclByName(aclNum);

            /* parse and add rule to ACL (but ONLY IPv4) */
            if ( resolveAccessListType(aclNum) != ERROR_FLAG )
            {
                tmp_curentAcl->pushBack(handleAccessList(aclNum, tmp_curentAcl->size(), tmp_buffer).release());
            }
        }
        /****************************/
        /* command "ip access-list" */
        else if ( cmd == CMD_IP_ACCESS_LIST )
        {
            tmp_buffer += tmp_extracted;        /* shift after "ip access-list " to first next character */
            
            int aclType = resolveAccessListType(tmp_buffer, tmp_extracted);
            if ( aclType == ERROR_FLAG )
            {
                continue;
            }

            tmp_buffer += tmp_extracted;        /* shift after "typ acl" to first next character */
            /* get ACL to add new rule */
            AccessControlList* tmp_curentAcl = getAclByName(parseAccessListName(tmp_buffer));

            /* reading rules of named ACL */
            while ( !inputStream.eof() )
            {
                inputStream.getline(buffer, 256);
                tmp_buffer = buffer;

                /* get the type of rule in line */
                if ( isspace(buffer[0]) )
                {
                    skipWhiteChars(buffer, tmp_extracted);
                    tmp_buffer += tmp_extracted;
                }

                /* if there is sequence number before the command -> skip */
                int tmp = 0;
                while ( isdigit(tmp_buffer[tmp]) )
                {
                    tmp++;
                }
                if ( tmp != 0 )
                {
                    tmp_buffer += tmp;
                    skipWhiteChars(tmp_buffer, tmp_extracted);
                    tmp_buffer += tmp_extracted;
                }
        
                /* find out the type of the rule in line */
                int cmd = parseCommand(tmp_buffer, tmp_extracted);

                /* if the rule is REMARK -> continue to the next */
                if ( cmd == CMD_ACL_RULE_REMARK )
                {
                    continue;
                }
                /* if it is not the rule of named ACL, return read line and break the cycle! */
                else if ( cmd != CMD_IP_ACCESS_LIST_RULE )
                {
                    rollbackStream(inputStream, inputStream.gcount());
                    break;
                }
                
                /* the rule of the standard ACL */
                if ( aclType == ACL_STANDARD )
                {
                    tmp_curentAcl->pushBack(handleStandardRule(tmp_curentAcl->size(), tmp_buffer).release());
                }
                /* the rule of the extended ACL */
                else
                {
                    tmp_curentAcl->pushBack(handleExtendedRule(tmp_curentAcl->size(), tmp_buffer).release());
                }
            }
        }
        else
        {
            continue;
        }
    }

    /* clear the map */
    m_aclsByName.clear();
    
    return m_aclsVector;
}