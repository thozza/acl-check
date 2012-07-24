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

#include <string>
#include "Exception.hpp"

/**
 * Class constructor.
 *
 * Initializes the message of exception to string "Unknown exception!".
 */
Exception::Exception() : std::exception(), m_msg("Unknown exception!") { }

//-----------------------------------------------------------------------------------

/**
 * Class constructor initializes the message of eception with passed string.
 *
 * @param msg string containing the text of exception.
 */
Exception::Exception(const std::string& msg) : std::exception(), m_msg(msg) { }

//-----------------------------------------------------------------------------------

/**
 * Method returns the string representing passed exception.
 *
 * @return returns pointer to string containing the message representing the exception.
 */
const char* Exception::what() const throw()
{
    return m_msg.c_str();
}

//-----------------------------------------------------------------------------------

/**
 * Method returns string with representation of the exception.
 *
 * @return returns the string in format "Exception: <msg>!", where <msg> is message
 * representing the exception.
 */
std::string Exception::toString() const
{
    std::string tmp("Exception: ");
    tmp.append(m_msg);

    return tmp;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the string of the message representing the exception.
 *
 * @return returns the string of the message representing the exception.
 */
std::string Exception::getMessage() const
{
    return m_msg;
}