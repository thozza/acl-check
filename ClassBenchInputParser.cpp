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

#include <cstdio>
#include <iostream>
#include <sstream>

#include "GlobalDefs.hpp"
#include "ClassBenchInputParser.hpp"

using namespace std;

/**
 * Method parses IPv4 address from passed string.
 *
 * Method parses IPv4, network mask or wildcard from passed string.
 *
 * @param str pointer to string containing IP address.
 * @return structure IP_ADDRESS containing parsed IP address.
 */
IP_ADDRESS ClassBenchInputParser::parseIPv4address(const char* str)
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
 * Method returns the structure IP_ADDRESS containing the network mask with passed number of bits.
 *
 * @param numOfBits number of set bits (value 0-32).
 * @return structure IP_ADDRESS containing the corresponding network mask.
 */
IP_ADDRESS ClassBenchInputParser::getMask(unsigned numOfBits)
{
    IP_ADDRESS address;

    u_int32_t mask = 0xFFFFFFFF;
    unsigned bits = numOfBits % 33;     /* maska moze byt 0-32 */

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
 * Metod parses the passed IPv4 address with mask and sets start and end address of the range.
 *
 * @param str pointer to string containing the IP address with mask "/xx".
 * @param rangeStart reference to the strucutre where the start IP address of the range will be stored.
 * @param rangeStop reference to the structure where the end IP address of the range will be stored.
 */
void ClassBenchInputParser::parseIPv4addressRange(const char* str, IP_ADDRESS& rangeStart, IP_ADDRESS& rangeStop)
{
    char buffer[32];
    stringstream ss;
    ss.str(str);
    IP_ADDRESS address;
    IP_ADDRESS mask;

    ss.getline(buffer, 32, '/');
    address = parseIPv4address(buffer);

    ss.getline(buffer, 32, '/');
    mask = getMask((unsigned) stringToInt(buffer));

    *((u_int32_t*)&rangeStart) = *((u_int32_t*)&address) & *((u_int32_t*)&mask);
    *((u_int32_t*)&rangeStop) = *((u_int32_t*)&rangeStart) | ~(*((u_int32_t*)&mask));
}

//-----------------------------------------------------------------------------------

/**
 * Method parses the port range and sets the start and end value of the range.
 *
 * @param str pointer to string containing the port range.
 * @param rangeStart reference to variable where the start value of the range will be stored.
 * @param rangeStop reference to the variable where the end value of the range will be stored.
 */
void ClassBenchInputParser::parsePortsRange(const char* str, u_int16_t& rangeStart, u_int16_t& rangeStop)
{
    char buffer[32];
    stringstream ss;
    ss.str(str);

    ss.getline(buffer, 32, ':');
    rangeStart = (u_int16_t) stringToInt(buffer);
    
    ss.getline(buffer, 32, ':');
    rangeStop = (u_int16_t) stringToInt(buffer);
}

//-----------------------------------------------------------------------------------

/**
 * Method parses numerical value of the protocol from passed string.
 *
 * @param str pointer to string containing (HEXA) numerical value of the protocol.
 * @return numerical value of the protocol from the string.
 */
int ClassBenchInputParser::parseProtocol(const char* str)
{
    stringstream ss;
    char buffer[8];
    unsigned protoNum;
    unsigned protoMask;

    ss.str(str);

    ss.getline(buffer, 8, '/');
    sscanf(buffer, "%X", &protoNum);

    ss.getline(buffer, 8, '/');
    sscanf(buffer, "%X", &protoMask);

    #ifdef DEBUG
    cerr << "protoNum= \"" << protoNum << "\"" << endl;
    cerr << "protoMask= \"" << protoMask << "\"" << endl;
    #endif
    
    if ( (protoNum == 0) && (protoMask == 0) )
    {
        return PROTO_IPv4;
    }
    else
    {
        return (int)( protoNum & protoMask );
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method parses the numerical value from the passed string.
 *
 * @param str pointer to string containing the numerical value.
 * @return numerical value from the string.
 */
int ClassBenchInputParser::stringToInt(const char* str)
{
    char buffer[16];
    stringstream ss;
    ss.str(str);
    ss.getline(buffer, 16);

    return atoi(buffer);
}

//-----------------------------------------------------------------------------------

/**
 * Method parses passed input stream and returns the vector of parsed ACL with corresponding rules.
 *
 * @param inputStream reference to input stream std::istream containing input configuration.
 * @return smart pointer containing the pointer to the vector of ACL with rules.
 */
auto_ptr< boost::ptr_vector< AccessControlList > > ClassBenchInputParser::parse(std::istream& inputStream)
{
    /* use smart pointer to store address and control allocated memory */
    auto_ptr< boost::ptr_vector< AccessControlList > > aclsVector(new boost::ptr_vector< AccessControlList >);
    char line[128];     /* variable for reading a line */
    char value[32];     /* variable for storing the items of the rule in the line */
    
    AccessControlList* newAcl = new AccessControlList();
    aclsVector->push_back(newAcl);

    /************************************/
    /* parse the rules of ACL */
    unsigned position = 0;              /* the position of the rule */
    while ( !inputStream.eof() )
    {
        AclRule* newRule = NULL;
        IP_ADDRESS addr1, addr2;
        u_int16_t port1, port2;
        stringstream ss;
        inputStream.getline(line, 128);         /* read line with the rule */

        /* check if the line begins with "@" */
        if ( line[0] != '@' )
        {
            #ifdef DEBUG
            cerr << "ClassBenchInputParser-ERROR: Input ACL contain line that doesn't start with '@'!" << endl;
            #endif
            continue;
        }

        newRule = new AclRule(position);
        newAcl->pushBack(newRule);

        ss.str(&(line[1]));     /* skip first character '@' */

        /*************/
        /* SOURCE IP */
        ss.getline(value, 32, '\t');

        #ifdef DEBUG
        cerr << "srcIP string= \"" << value << "\"" << endl;
        #endif

        parseIPv4addressRange(value, addr1, addr2);
        newRule->setSrcIP(addr1, addr2);

        /******************/
        /* DESTINATION IP */
        ss.getline(value, 32, '\t');

        #ifdef DEBUG
        cerr << "dstIP string= \"" << value << "\"" << endl;
        #endif

        parseIPv4addressRange(value, addr1, addr2);
        newRule->setDstIP(addr1, addr2);

        /***************/
        /* SOURCE PORT */
        ss.getline(value, 32, '\t');

        #ifdef DEBUG
        cerr << "srcPort string= \"" << value << "\"" << endl;
        #endif

        parsePortsRange(value, port1, port2);
        newRule->setSrcPort(port1, port2);

        /********************/
        /* DESTINATION PORT */
        ss.getline(value, 32, '\t');

        #ifdef DEBUG
        cerr << "dstPort string= \"" << value << "\"" << endl;
        #endif

        parsePortsRange(value, port1, port2);
        newRule->setDstPort(port1, port2);

        /************/
        /* PROTOCOL */
        ss.getline(value, 32, '\t');

        #ifdef DEBUG
        cerr << "proto string= \"" << value << "\"" << endl;
        #endif

        newRule->setProtocol(parseProtocol(value));

        /**********/
        /* ACTION */
        newRule->setAction(ACTION_ALLOW);
        
        ++position;
    }

    return aclsVector;
}
