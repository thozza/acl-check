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

#include <memory>
#include <vector>

#include "InputParser.hpp"

#ifndef XML_INPUTPARSER_H__89723645878378901287845879128767357829338
#define XML_INPUTPARSER_H__89723645878378901287845879128767357829338

/**
 * Class XmlInputParser represents input parser of XML file in specific format.
 *
 * Class provides only one public method parse() which is used to parse XML
 * configuration entered as an input data stream std::istream. Method output
 * is smart pointer to vector containing all parsed ACLs from configuration.
 */
class XmlInputParser : public InputParser
{
    protected:
         static void parseIpRange(IP_ADDRESS& ipRangeStart, IP_ADDRESS& ipRangeStop, char *string);
         static void parsePortRange(u_int16_t& portRangeStart, u_int16_t& portRangeStop, char *string);
         static int parseProtocol(char *string);
         static int parseAction(char *string);
        
    public:
        virtual std::auto_ptr< boost::ptr_vector< AccessControlList > > parse(std::istream& inputStream) throw(Exception);
};

#endif /* XML_INPUTPARSER_H__89723645878378901287845879128767357829338 */