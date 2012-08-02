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

#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <string>

#include "rapidxml/rapidxml.hpp"

#include "AccessControlList.hpp"
#include "AclRule.hpp"
#include "XmlInputParser.hpp"
#include "GlobalDefs.hpp"

using namespace std;
using namespace rapidxml;

/**
 * Method parses passed IPv4 address range and sets start and end address of the range
 *
 * @param ipRangeStart reference to the structure where the start IP address will be stored.
 * @param ipRangeStop reference to the structure where the end IP address will be stored.
 * @param string pointer to string containing IP address range.
 */
void XmlInputParser::parseIpRange(IP_ADDRESS& ipRangeStart, IP_ADDRESS& ipRangeStop, char *string)
{
    IP_ADDRESS addrMin = {0, 0, 0, 0};
    IP_ADDRESS addrMax = {255, 255, 255, 255};

    ipRangeStart = addrMin;
    ipRangeStop = addrMax;
    
    /* parameters check */
    if ( string == NULL )
    {
        cerr << "ERROR-XmlInputParser: Parsing SRC IP got NULL pointer string!";
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        return;
    }

    if ( strcmp(string, "any") == 0 )
    {
        return;
    }

    char tmp[4];
    stringstream ss;
    ss.str(string);

    ss.getline(tmp, 4, '.');
    ipRangeStart.A = atoi(tmp);
    ss.getline(tmp, 4, '.');
    ipRangeStart.B = atoi(tmp);
    ss.getline(tmp, 4, '.');
    ipRangeStart.C = atoi(tmp);
    ss.getline(tmp, 4, '-');
    ipRangeStart.D = atoi(tmp);

    ss.getline(tmp, 4, '.');
    ipRangeStop.A = atoi(tmp);
    ss.getline(tmp, 4, '.');
    ipRangeStop.B = atoi(tmp);
    ss.getline(tmp, 4, '.');
    ipRangeStop.C = atoi(tmp);
    ss.getline(tmp, 4, '.');
    ipRangeStop.D = atoi(tmp);
}

//--------------------------------------------------------------------------------

/**
 * Method parses port range and sets start and end port of the range.
 *
 * @param portRangeStart reference to variable, where the start port will be stored.
 * @param portRangeStop reference to variable, where the end port will be stored.
 * @param string pointer to string containing port range.
 */
void XmlInputParser::parsePortRange(u_int16_t& portRangeStart, u_int16_t& portRangeStop, char *string)
{
    portRangeStart = 0x0000;
    portRangeStop = 0xFFFF;

    /* parameters check */
    if ( string == NULL )
    {
        cerr << "ERROR-XmlInputParser: Parsing SRC PORT got NULL pointer string!";
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        return;
    }

    if ( strcmp(string, "any") == 0 )
    {
        return;
    }

    char tmp[10];
    stringstream ss;
    ss.str(string);

    ss.getline(tmp, 10, '-');
    portRangeStart = atoi(tmp);
    ss.getline(tmp, 10, '-');
    portRangeStop = atoi(tmp);
}

//--------------------------------------------------------------------------------

/**
 * Method parses the protocol from given string.
 *
 * @param string pointer to string containing the protocol name.
 * @return PROTO_XXX - value representing known protocol.
 *         Value representing unknown / non-registered protocol (value up to max. 255).
 */
int XmlInputParser::parseProtocol(char* string)
{
    if ( string == NULL )
    {
        cerr << "ERROR-XmlInputParser: Parsing PROTOCOL got NULL pointer string!";
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        return PROTO_ANY;
    }

    if ( strcmp(string, "ip") == 0 )
    {
        return PROTO_IPv4;
    }
    else if ( strcmp(string, "icmp") == 0 )
    {
        return PROTO_ICMPv4;
    }
    else if ( strcmp(string, "tcp") == 0 )
    {
        return PROTO_TCP;
    }
    else if ( strcmp(string, "udp") == 0 )
    {
        return PROTO_UDP;
    }
    else
    {
        return PROTO_ANY;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method parses the rule action from given string.
 *
 * @param string pointer to string containing the action.
 * @return value representing the rule action (ACTION_XXX).
 */
int XmlInputParser::parseAction(char* string)
{
    if ( string == NULL )
    {
        cerr << "ERROR-XmlInputParser: Parsing ACTION got NULL pointer string!";
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        return ACTION_DENY;
    }

    if ( strcmp(string, "permit") == 0 )
    {
        return ACTION_ALLOW;
    }
    else
    {
        return ACTION_DENY;
    }
}

//--------------------------------------------------------------------------------

/**
 * Method parses passed input stream and returns a ector of parsed ACLs wit their rules.
 *
 * @throw Exception when error occures, method throws exception.
 * @param inputStream reference to input stream std::istream containing input configuration.
 * @return smart pointer containing pointer to vector of ACLs with their rules.
 */
std::auto_ptr< boost::ptr_vector< AccessControlList > > XmlInputParser::parse(std::istream& inputStream) throw(Exception)
{
    /* use smart vector to store address and control allocated memory */
    auto_ptr< boost::ptr_vector< AccessControlList > > aclsVector(new boost::ptr_vector< AccessControlList >);
    unsigned long inputFileLength = 0;
    
    /* get the size of input XML */
    inputStream.seekg (0, ios_base::end);
    inputFileLength = inputStream.tellg();      /* get the position of the offset in stream (the size of the stream) */
    inputStream.seekg (0, ios_base::beg);
    inputFileLength++;                          /* for appending "/0" */

    #ifdef XML_PARSER_DEBUG
    cerr << endl << "DEBUG: Input length= " << inputFileLength << endl;
    #endif

    /* if the stream contains less than one character */
    if ( inputFileLength < 1 )
        throw Exception("Cannot parse input file! File is empty!");

    /*************************************************/
    /* allocation of the buffer for reading the file */
    char* tmp = NULL;
    if ( (tmp = new char[inputFileLength]) == NULL )
    {
        cerr << "ERROR-XmlInputParser: Not enough memory to alocate buffer for input XML file!";
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
    xml_attribute< >* tmp_xmlAttribute = NULL;

    /**************************************/
    /* parsing the buffer to DOM XML tree */
    try {
        xmlParsedDoc.parse<0>(tmp);
    }
    catch (parse_error e)
    {
        cerr << "ERROR-XmlInputParser: Parsing of XML file failed!";
        #ifdef DEBUG
        cerr << " (rapidxml::parse_error) (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        cerr << endl << "WHAT: " << e.what() << endl;
        cerr << "WHERE: " << e.where<char>();
        #endif
        cerr << endl;

        delete[](tmp);
        
        throw Exception("Parsing of input file failed!");
    }

    /****************************************/
    /* parse every existing ACL in XML file */
    for ( tmp_accessListNode = xmlParsedDoc.first_node("ecm:access-list");
          tmp_accessListNode != NULL;
          tmp_accessListNode = tmp_accessListNode->next_sibling("ecm:access-list") )
    {
        /* if ACL does not contain any rules, continue */
        if ( tmp_accessListNode->first_node("ecm:rule") == NULL )
        {
            #ifdef XML_PARSER_DEBUG
            cerr << "DEBUG: Input contain ACL without rules!" << endl;
            #endif

            continue;
        }

        AccessControlList* newAcl = NULL;
        xml_node< >* tmpRuleNode = NULL;

        /* get ACL ID */
        if ( (tmp_xmlAttribute = tmp_accessListNode->first_attribute("id")) == NULL )
        {
            newAcl = new AccessControlList();
        }
        else
        {
            newAcl = new AccessControlList(string(tmp_xmlAttribute->value()));
        }

        aclsVector->push_back(newAcl);

        unsigned pos;
        /* read all rules of the actual ACL */
        for ( pos = 0, tmpRuleNode = tmp_accessListNode->first_node("ecm:rule");
              tmpRuleNode != NULL;
              ++pos, tmpRuleNode = tmpRuleNode->next_sibling("ecm:rule") )
        {
            AclRule* newRule = new AclRule(pos);
            newAcl->pushBack(newRule);
            IP_ADDRESS tmpIp1;
            IP_ADDRESS tmpIp2;
            
            /* action */
            newRule->setAction(XmlInputParser::parseAction(tmpRuleNode->first_attribute("action")->value()));
            /* protocol */
            newRule->setProtocol(XmlInputParser::parseProtocol(tmpRuleNode->first_attribute("protocol")->value()));
            /* source IP */
            XmlInputParser::parseIpRange(tmpIp1, tmpIp2, tmpRuleNode->first_attribute("source")->value());
            newRule->setSrcIP(tmpIp1, tmpIp2);
            /* destination IP */
            XmlInputParser::parseIpRange(tmpIp1, tmpIp2, tmpRuleNode->first_attribute("destination")->value());
            newRule->setDstIP(tmpIp1, tmpIp2);
        }
    }

    xmlParsedDoc.clear();       /* delete the DOM tree of the XML file */
    delete[](tmp);
    
    return aclsVector;
}