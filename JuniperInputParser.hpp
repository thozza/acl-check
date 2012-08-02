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

#include "rapidxml/rapidxml.hpp"

#include "InputParser.hpp"

#ifndef JUNIPER_INPUTPARSER_HPP__5738956718923456885728987324657328435421947165873429
#define JUNIPER_INPUTPARSER_HPP__5738956718923456885728987324657328435421947165873429

/**
 * Class JuniperInputParser represents input parser of Juniper configuration file.
 *
 * Class provides only one public method parse() which is used to parse Juniper
 * configuration entered as an input data stream std::istream. Method output
 * is smart pointer to vector containing all parsed ACLs from configuration.
 */
class JuniperInputParser : public InputParser
{
    protected:
        IP_ADDRESS parseIPv4address(const char* str);
        IP_ADDRESS getMask(unsigned numOfBits);
        void parseIPv4addressRange(const char* str, IP_ADDRESS& rangeStart, IP_ADDRESS& rangeStop);

        void parsePortsRange(const char* str, u_int16_t& rangeStart, u_int16_t& rangeStop);
        u_int16_t parsePortByName(const char* str);

        int parseProtocol(const char* str);
        
        int stringToInt(const char* str);
    
    public:
        JuniperInputParser() { };
        virtual ~JuniperInputParser() { };
        virtual std::auto_ptr< boost::ptr_vector< AccessControlList > > parse(std::istream& inputStream);
};

#endif /* JUNIPER_INPUTPARSER_HPP__5738956718923456885728987324657328435421947165873429 */
