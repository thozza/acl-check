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

#include <iostream>
#include <sstream>

#include "GlobalDefs.hpp"
#include "JuniperInputParser.hpp"

using namespace std;
using namespace rapidxml;

/**
 * Method parses IPv4 address from passed string.
 *
 * Method parses IPv4 address,
 * network mask, or wildcard from passed string.
 *
 * @param str pointer to string containing IP address.
 * @return the structure IP_ADDRESS containing parsed IP address.
 */
IP_ADDRESS JuniperInputParser::parseIPv4address(const char* str)
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

//-----------------------------------------------------------------------------------

/**
 * Method returns the structure IP_ADDRESS containing network mask with passed number of bits
 * @param numOfBits number of bits that represent the network mask (value 0-32).
 * @return the structure IP_ADDRESS containing the mask.
 */
IP_ADDRESS JuniperInputParser::getMask(unsigned numOfBits)
{
    IP_ADDRESS address;

    u_int32_t mask = 0xFFFFFFFF;
    unsigned bits = numOfBits % 33;     /* mask can be 0-32 */

    if ( bits == 0 )
    {
        mask = 0x00000000;
    }
    else
    {
        mask <<= (32 - bits);
    }

    *((u_int32_t*)&address) = mask;

    return address;
}

//-----------------------------------------------------------------------------------

/**
 * Method parses passed IPv4 address with network mask and sets start and end address of the range.
 *
 * @param str pointer to string containing IP address (also with mask "/xx").
 * @param rangeStart reference to the structure where the start IP address will be stored.
 * @param rangeStop reference to the structure where the end IP address will be stored.
 */
void JuniperInputParser::parseIPv4addressRange(const char* str, IP_ADDRESS& rangeStart, IP_ADDRESS& rangeStop)
{
    char buffer[32];
    stringstream ss;
    ss.str(str);
    IP_ADDRESS address;
    IP_ADDRESS mask;
    
    ss.getline(buffer, 32, '/');
    address = parseIPv4address(buffer);

    /* try whether the adress contains also mask */
    if ( ss.eof() )
    {
        rangeStop = rangeStart = address;
    }
    /* there was a mask */
    else
    {
        ss.getline(buffer, 32, '/');
        mask = getMask((unsigned) stringToInt(buffer));

        *((u_int32_t*)&rangeStart) = *((u_int32_t*)&address) & *((u_int32_t*)&mask);
        *((u_int32_t*)&rangeStop) = *((u_int32_t*)&rangeStart) | ~(*((u_int32_t*)&mask));
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method parses port's numerical value from its string name.
 *
 * @param str pointer to string containing line with name of the port as a string.
 * @return numerical value representing the port number.
 */
u_int16_t JuniperInputParser::parsePortByName(const char* str)
{
    switch ( str[0] )
    {
        case 'a':
            /* afs */
            return PORT_AFS;
            
        case 'b':
            if ( strncmp(str, "bgp", 3) == 0 )
            {
                return PORT_BGP;
            }
            else if ( strncmp(str, "biff", 4) == 0 )
            {
                return PORT_BIFF;
            }
            else if ( strncmp(str, "bootpc", 6) == 0 )
            {
                return PORT_BOOTPC;
            }
            /* bootps */
            else
            {
                return PORT_BOOTPS;
            }

        case 'c':
            if ( strncmp(str, "cvspserver", 10) == 0 )
            {
                return PORT_CVSPSERVER;
            }
            /* cmd */
            else
            {
                return PORT_CMD;
            }

        case 'd':
            if ( strncmp(str, "dhcp", 4) == 0 )
            {
                return PORT_DHCP;
            }
            /* domain */
            else
            {
                return PORT_DOMAIN;
            }

        case 'e':
            if ( strncmp(str, "eklogin", 7) == 0 )
            {
                return PORT_EKLOGIN;
            }
            else if ( strncmp(str, "ekshell", 7) == 0 )
            {
                return PORT_EKSHELL;
            }
            /* exec */
            else
            {
                return PORT_EXEC;
            }

        case 'f':
            if ( strncmp(str, "finger", 6) == 0 )
            {
                return PORT_FINGER;
            }
            else if ( strncmp(str, "ftp", 3) == 0 )
            {
                return PORT_FTP;
            }
            /* ftp-data */
            else
            {
                return PORT_FTP_DATA;
            }

        case 'h':
            if ( strncmp(str, "http", 4) == 0 )
            {
                return PORT_WWW;
            }
            /* https */
            else
            {
                return PORT_HTTPS;
            }

        case 'i':
            if ( strncmp(str, "ident", 5) == 0 )
            {
                return PORT_IDENT;
            }
            /* imap */
            else
            {
                return PORT_IMAP;
            }

        case 'k':
            if ( strncmp(str, "kerberos-sec", 12) == 0 )
            {
                return PORT_KERBEROS_SEC;
            }
            else if ( strncmp(str, "klogin", 6) == 0 )
            {
                return PORT_KLOGIN;
            }
            else if ( strncmp(str, "kpasswd", 7) == 0 )
            {
                return PORT_KPASSWD;
            }
            else if ( strncmp(str, "krb-prop", 8) == 0 )
            {
                return PORT_KRB_PROP;
            }
            else if ( strncmp(str, "krbupdate", 9) == 0 )
            {
                return PORT_KRBUPDATE;
            }
            /* kshell */
            else
            {
                return PORT_KSHELL;
            }

        case 'l':
            if ( strncmp(str, "login", 5) == 0 )
            {
                return PORT_LOGIN;
            }
            else if ( strncmp(str, "ldap", 4) == 0 )
            {
                return PORT_LDAP;
            }
            /* ldp */
            else
            {
                return PORT_LDP;
            }

        case 'm':
            if ( strncmp(str, "msdp", 4) == 0 )
            {
                return PORT_MSDP;
            }
            else if ( strncmp(str, "mobilip-mn", 10) == 0 )
            {
                return PORT_MOBIL_IP_MN;
            }
            /* mobileip-agent */
            else
            {
                return PORT_MOBILE_IP;
            }

        case 'n':
            if ( strncmp(str, "netbios-dgm", 11) == 0 )
            {
                return PORT_NETBIOS_DGM;
            }
            else if ( strncmp(str, "netbios-ns", 10) == 0 )
            {
                return PORT_NETBIOS_NS;
            }
            else if ( strncmp(str, "netbios-ssn", 11) == 0 )
            {
                return PORT_NETBIOS_SS;
            }
            else if ( strncmp(str, "nfsd", 4) == 0 )
            {
                return PORT_NFSD;
            }
            else if ( strncmp(str, "nntp", 4) == 0 )
            {
                return PORT_NNTP;
            }
            else if ( strncmp(str, "ntalk", 5) == 0 )
            {
                return PORT_NTALK;
            }
            /* ntp */
            else
            {
                return PORT_NTP;
            }

        case 'p':
            if ( strncmp(str, "pptp", 4) == 0 )
            {
                return PORT_PPTP;
            }
            else if ( strncmp(str, "pop3", 4) == 0 )
            {
                return PORT_POP3;
            }
            /* printer */
            else
            {
                return PORT_LPD;
            }

        case 'r':
            if ( strncmp(str, "radacct", 7) == 0 )
            {
                return PORT_RADACCT;
            }
            else if ( strncmp(str, "radius", 6) == 0 )
            {
                return PORT_RADIUS;
            }
            else if ( strncmp(str, "rkinit", 6) == 0 )
            {
                return PORT_RKINIT;
            }
            /* rip */
            else
            {
                return PORT_RIP;
            }

        case 's':
            if ( strncmp(str, "smtp", 4) == 0 )
            {
                return PORT_SMTP;
            }
            else if ( strncmp(str, "snmp", 4) == 0 )
            {
                return PORT_SNMP;
            }
            else if ( strncmp(str, "snmptrap", 8) == 0 )
            {
                return PORT_SNMPTRAP;
            }
            else if ( strncmp(str, "snpp", 4) == 0 )
            {
                return PORT_SNPP;
            }
            else if ( strncmp(str, "socks", 5) == 0 )
            {
                return PORT_SOCKS;
            }
            else if ( strncmp(str, "ssh", 3) == 0 )
            {
                return PORT_SSH;
            }
            else if ( strncmp(str, "sunrpc", 6) == 0 )
            {
                return PORT_SUNRPC;
            }
            /* syslog */
            else
            {
                return PORT_SYSLOG;
            }

        case 't':
            if ( strncmp(str, "tacacs", 6) == 0 )
            {
                return PORT_TACACS;
            }
            else if ( strncmp(str, "tacacs-ds", 9) == 0 )
            {
                return PORT_TACACS_DS;
            }
            else if ( strncmp(str, "talk", 4) == 0 )
            {
                return PORT_TALK;
            }
            else if ( strncmp(str, "telnet", 6) == 0 )
            {
                return PORT_TELNET;
            }
            else if ( strncmp(str, "tftp", 4) == 0 )
            {
                return PORT_TFTP;
            }
            /* timed */
            else
            {
                return PORT_TIMED;
            }

        case 'w':
            if ( strncmp(str, "who", 3) == 0 )
            {
                return PORT_WHO;
            }
            /* whois */
            else
            {
                return PORT_WHOIS;
            }

        case 'z':
            if ( strncmp(str, "zephyr-clt", 10) == 0 )
            {
                return PORT_ZEPHYR_CLT;
            }
            /* zephyr-hm */
            else
            {
                return PORT_ZEPHYR_HM;
            }

        /* xdmcp */
        default:
            return PORT_XDMCP;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method parses port range, or one port and sets start and end port of the range.
 *
 * @param str pointer to string containing port range, por one port, given as a number or by string name.
 * @param rangeStart reference to variable, where the start port will be stored.
 * @param rangeStop reference to variable, where the end port will be stored.
 */
void JuniperInputParser::parsePortsRange(const char* str, u_int16_t& rangeStart, u_int16_t& rangeStop)
{
    char buffer[32];
    stringstream ss;
    ss.str(str);

    ss.getline(buffer, 32, '-');
    /* name of the port */
    if ( isalpha(buffer[0]) )
    {
        rangeStart = parsePortByName(buffer);
    }
    /* number of the port */
    else
    {
        rangeStart = (u_int16_t) stringToInt(buffer);
    }

    /* ry whether it was a range or not */
    if ( ss.eof() )
    {
        rangeStop = rangeStart;
    }
    /* it was a range */
    else
    {
        ss.getline(buffer, 32, '-');
        /* name of the port */
        if ( isalpha(buffer[0]) )
        {
            rangeStop = parsePortByName(buffer);
        }
        /* number of the port */
        else
        {
            rangeStop = (u_int16_t) stringToInt(buffer);
        }
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method parses the protocol from given string.
 *
 * @param str pointer to string containing line with the protocol.
 * @return PROTO_XXX - value representing known protocol.
 *         Value representing unknown / non-registered protocol (value up to max. 255).
 */
int JuniperInputParser::parseProtocol(const char* str)
{
    switch ( str[0] )
    {
        case 'a':
            /* protocol "ah" */
            return PROTO_AH;

        case 'd':
            /* protocol "dstopts" */
            return PROTO_IPv6_OPTS;

        case 'e':
            /* protocols "esp" and "egp" */
            switch ( str[1] )
            {
                case 's':
                    /* protocol "esp" */
                    return PROTO_ESP;

                default:
                    /* protocol "egp" */
                    return PROTO_EGP;
            }

        case 'f':
            /* protocol "fragment" */
            return PROTO_IPv4_IPv6_FRAG;
            
        case 'g':
            /*  protocol "gre" */
            return PROTO_GRE;

        case 'h':
            /* protocol "hop-by-hop" */
            return PROTO_HOPOPT;

        case 'i':
            /* protocols "icmp", "icmp6", "icmpv6", "igmp", "ipinip" and "ipv6" */
            switch ( str[1] )
            {
                case 'c':
                    if ( strncmp(str, "icmp", 4) == 0 )
                    {
                        return PROTO_ICMPv4;
                    }
                    /* protocols "icmp6" and "icmpv6" */
                    else
                    {
                        return PROTO_IPv6_ICMP;
                    }

                case 'g':
                    /* protocol "igmp" */
                    return PROTO_IGMP;

                default:
                    /* protocols "ipinip" and "ipv6" */
                    switch ( str [2])
                    {
                        case 'i':
                            /* protocol "ipinip" */
                            return PROTO_IP_IN_IP;

                        default:
                            /* protocol "ipv6" */
                            return PROTO_IPv4_IPv6;
                    }
            }
            
        case 'n':
            /* protocol "no-next-header" */
            return PROTO_IPv6_NONXT;

        case 'o':
            /* protocol "ospf" */
            return PROTO_OSPF;

        case 'p':
            /* protocol "pim" */
            return PROTO_PIM;

        case 'r':
            /* protocol "routing" */
            if ( strncmp(str, "routing", 7) == 0 )
            {
                return PROTO_IPv4_IPv6_ROUTE;
            }
            /* protocol "rsvp" */
            else
            {
                return PROTO_RSVP;
            }

        case 's':
            /* protocol "sctp" */
            return PROTO_SCTP;
            
        case 't':
            /* protocol "tcp" */
            return PROTO_TCP;

        case 'u':
            /* protocol "udp" */
            return PROTO_UDP;

        case 'v':
            /* protocol "vrrp" */
            return PROTO_VRRP;
            
        default:
            return stringToInt(str);
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method parses the numerical value from the string.
 * @param str pointer to string containing a numerical value.
 * @return numerical value from string.
 */
int JuniperInputParser::stringToInt(const char* str)
{
    char buffer[16];
    stringstream ss;
    ss.str(str);
    ss.getline(buffer, 16);

    return atoi(buffer);
}

//-----------------------------------------------------------------------------------

/**
 * Method parses passed input stream and returns a ector of parsed ACLs wit their rules.
 *
 * @param inputStream reference to input stream std::istream containing input configuration.
 * @return smart pointer containing pointer to vector of ACLs with their rules.
 */
std::auto_ptr< boost::ptr_vector< AccessControlList > > JuniperInputParser::parse(std::istream& inputStream)
{
    /* use smart vector to store address and control allocated memory */
    auto_ptr< boost::ptr_vector< AccessControlList > > aclsVector(new boost::ptr_vector< AccessControlList >);
    unsigned long inputFileLength = 0;

    /* get the size of input XML */
    inputStream.seekg (0, ios_base::end);
    inputFileLength = inputStream.tellg();      /* get the position of the offset in stream (the size of the stream) */
    inputStream.seekg (0, ios_base::beg);
    inputFileLength++;                          /* append "/0" */

    #ifdef DEBUG
    cerr << endl << "DEBUG: Input length= " << inputFileLength << endl;
    #endif

    /* if the stream contains less than one character */
    if ( inputFileLength < 1 )
        throw Exception("Cannot parse input file! File is empty!");

    /**********************************************************************/
    /* allocation of the buffer for reading the file */
    char* tmp = NULL;
    if ( (tmp = new char[inputFileLength]) == NULL )
    {
        cerr << "ERROR-JuniperInputParser: Not enough memory to alocate buffer for input XML file!";
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        throw Exception("Parsing of input file failed!");
    }

    inputStream.read(tmp, (inputFileLength - 1));      /* reading the input from stream to the buffer */
    tmp[inputFileLength - 1] = '\0';                   /* append NULL for RapidXML parser */

    /* pointers necessary for working with parsed XML file */
    xml_document< > xmlParsedDoc;
    xml_node< >* tmp_accessListNode = NULL;

    /****************************************/
    /* parsing the buffer to DOM XML tree */
    try {
        xmlParsedDoc.parse<0>(tmp);
    }
    catch (parse_error e)
    {
        /* parsing error */
        cerr << "ERROR-JuniperInputParser: Parsing of XML file failed!";
        #ifdef DEBUG
        cerr << " (rapidxml::parse_error) (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        cerr << endl << "WHAT: " << e.what() << endl;
        cerr << "WHERE: " << e.where<char>();
        #endif
        cerr << endl;

        delete[](tmp);

        throw Exception("Parsing of input file failed!");
    }

    /***********************************************************************/
    /* parsing all existing ACLs in XML file */
    /* RPC-REPLY */
    if ( (tmp_accessListNode = xmlParsedDoc.first_node("rpc-reply")) == NULL )
    {
        throw Exception("Input configuration has wrong format! \"rpc-reply\" node is missing!");
    }

    /* CONFIGURATION */
    if ( (tmp_accessListNode = tmp_accessListNode->first_node("configuration")) == NULL )
    {
        throw Exception("Input configuration has wrong format! \"configuration\" node is missing!");
    }

    /* FIREWALL */
    if ( (tmp_accessListNode = tmp_accessListNode->first_node("firewall")) == NULL )
    {
        throw Exception("Input configuration doesn't contain \"firewall\" node!");
    }

    /* if the IPv4 family is set, move to that node, otherwise continue where we are */
    if ( tmp_accessListNode->first_node("inet") != NULL )
        tmp_accessListNode = tmp_accessListNode->first_node("inet");

    /* parsing all FILTER - ACLs */
    for ( tmp_accessListNode = tmp_accessListNode->first_node("filter");
          tmp_accessListNode != NULL;
          tmp_accessListNode = tmp_accessListNode->next_sibling("filter") )
    {
        /* if ACL does not ontains any rules, continue */
        if ( tmp_accessListNode->first_node("term") == NULL )
        {
            #ifdef DEBUG
            cerr << "DEBUG: Input contain ACL without rules!" << endl;
            #endif

            continue;
        }

        xml_node< >* nameNode = NULL;
        AccessControlList* newAcl = NULL;       /* pointer where new ACL is created */
        xml_node< >* tmpRuleNode = NULL;
        
        /* get the ID of ACL */
        if ( (nameNode = tmp_accessListNode->first_node("name")) == NULL )
        {
            newAcl = new AccessControlList();
        }
        else
        {
            newAcl = new AccessControlList(nameNode->value());
        }

        #ifdef DEBUG
        cerr << "New ACL created= \"" << newAcl->name() << "\"" << endl;
        #endif

        aclsVector->push_back(newAcl);    /* add new AccessControlList to ptr_vector */

        unsigned pos;
        /* reading all rules of current ACL */
        for ( pos = 0, tmpRuleNode = tmp_accessListNode->first_node("term");
              tmpRuleNode != NULL;
              ++pos, tmpRuleNode = tmpRuleNode->next_sibling("term") )
        {
            AclRule* newRule = NULL;
            xml_node< >* fromNode = NULL;
            xml_node< >* thenNode = NULL;

            /* get ID of the rule */
            if ( (nameNode = tmpRuleNode->first_node("name")) == NULL )
            {
                newRule= new AclRule(pos);
            }
            else
            {
                 newRule= new AclRule(pos, nameNode->value());
            }

            #ifdef DEBUG
            cerr << "New ACL rule created= \"" << newRule->getName() << "\"" << endl;
            #endif
            
            /**********/
            /* action */
            if ( (thenNode = tmpRuleNode->first_node("then")) != NULL )
            {
                /* if the action is ACCEPT */
                if ( thenNode->first_node("accept") != NULL )
                {
                    newRule->setAction(ACTION_ALLOW);
                }
                else if ( (thenNode->first_node("discard") != NULL) || (thenNode->first_node("reject") != NULL) )
                {
                    newRule->setAction(ACTION_DENY);
                }
                else
                {
                    delete(newRule);
                    continue;
                }
            }
            else
            {
                newRule->setAction(ACTION_ALLOW);
            }

            /********************/
            /* match conditions */
            if ( (fromNode = tmpRuleNode->first_node("from")) != NULL )
            {
                xml_node< >* tmpNode = NULL;
                IP_ADDRESS tmpIp1;
                IP_ADDRESS tmpIp2;

                /* PROTOCOL */
                if ( (tmpNode = fromNode->first_node("protocol")) != NULL )
                {
                    newRule->setProtocol(parseProtocol(tmpNode->value()));
                    tmpNode = NULL;
                }
                
                /* SOURCE-ADDRESS */
                if ( (tmpNode = fromNode->first_node("source-address")) != NULL )
                {
                    parseIPv4addressRange(tmpNode->first_node("name")->value(), tmpIp1, tmpIp2);
                    newRule->setSrcIP(tmpIp1, tmpIp2);
                    tmpNode = NULL;
                }

                /* DESTINATION-ADDRESS */
                if ( (tmpNode = fromNode->first_node("destination-address")) != NULL )
                {
                    parseIPv4addressRange(tmpNode->first_node("name")->value(), tmpIp1, tmpIp2);
                    newRule->setDstIP(tmpIp1, tmpIp2);
                    tmpNode = NULL;
                }

                /* is the protocol is TCP or UDP -> parsing also ports */
                if ( (newRule->getProtocol() == PROTO_TCP) || (newRule->getProtocol() == PROTO_UDP) )
                {
                    u_int16_t tmpPort1;
                    u_int16_t tmpPort2;
                
                    /* SOURCE-PORT */
                    if ( (tmpNode = fromNode->first_node("source-port")) != NULL )
                    {
                        parsePortsRange(tmpNode->value(), tmpPort1, tmpPort2);
                        newRule->setSrcPort(tmpPort1, tmpPort2);
                        tmpNode = NULL;
                    }
                    /* SOURCE-PORT-EXCEPT */
                    else if ( (tmpNode = fromNode->first_node("source-port-except")) != NULL )
                    {
                        parsePortsRange(tmpNode->value(), tmpPort1, tmpPort2);
                        newRule->setSrcPort(tmpPort1, tmpPort2, true);
                        tmpNode = NULL;
                    }

                    /* DESTINATION-PORT */
                    if ( (tmpNode = fromNode->first_node("destination-port")) != NULL )
                    {
                        parsePortsRange(tmpNode->value(), tmpPort1, tmpPort2);
                        newRule->setDstPort(tmpPort1, tmpPort2);
                        tmpNode = NULL;
                    }
                    /* DESTINATION-PORT-EXCEPT */
                    else if ( (tmpNode = fromNode->first_node("destination-port-except")) != NULL )
                    {
                        parsePortsRange(tmpNode->value(), tmpPort1, tmpPort2);
                        newRule->setDstPort(tmpPort1, tmpPort2, true);
                        tmpNode = NULL;
                    }
                }
            }

            newAcl->pushBack(newRule);                  /* add the rule to ACL */
        }
    }

    xmlParsedDoc.clear();       /* clear DOM tree of XML file */
    delete[](tmp);              /* free the memory of the buffer */

    return aclsVector;
}