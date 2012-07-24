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

/* Header file containing the declaration of the ClassBenchInputParser class,
 * which represents parser of the input given in following format:
 *
 * @168.88.86.208/30  170.227.150.64/28  750:750  110:110  0x11/0xFF  0x0000/0x0000
 * @srcIP             dstIP              srcPort  dstPort  protocol   protoFlags
 */

#include "InputParser.hpp"

#ifndef CLASSBENCH_INPUTPARSER_HPP__84687534487486441967447646697674684864876848646864
#define CLASSBENCH_INPUTPARSER_HPP__84687534487486441967447646697674684864876848646864

class ClassBenchInputParser : public InputParser
{
    private:
        IP_ADDRESS parseIPv4address(const char* str);
        IP_ADDRESS getMask(unsigned numOfBits);
        void parseIPv4addressRange(const char* str, IP_ADDRESS& rangeStart, IP_ADDRESS& rangeStop);

        void parsePortsRange(const char* str, u_int16_t& rangeStart, u_int16_t& rangeStop);

        int parseProtocol(const char* str);

        int stringToInt(const char* str);
        
    public:
        ClassBenchInputParser() { };
        virtual ~ClassBenchInputParser() { };
        virtual std::auto_ptr< boost::ptr_vector< AccessControlList > > parse(std::istream& inputStream);
};

#endif /* CLASSBENCH_INPUTPARSER_HPP__84687534487486441967447646697674684864876848646864 */