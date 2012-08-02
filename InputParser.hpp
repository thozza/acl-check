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

#include <boost/ptr_container/ptr_vector.hpp>
#include <memory>
#include <istream>

#include "ProtocolsDef.hpp"
#include "PortsDef.hpp"
#include "AccessControlList.hpp"

#ifndef INPUT_PARSER_H__56123789526737128938076372894801283804
#define INPUT_PARSER_H__56123789526737128938076372894801283804

/**
 * Class InputParser represents the interface of the input parser.
 *
 * Class declares virtual method "parse()", which must be implemented by any input parser.
 * The return value of the method is pointer to the vector
 * of access lists that contain the rules contained in input stream.
 */
class InputParser
{
    public:
        virtual ~InputParser() { };
        virtual std::auto_ptr< boost::ptr_vector< AccessControlList > > parse(std::istream& inputStream) = 0;
};

#endif /* INPUT_PARSER_H__56123789526737128938076372894801283804 */