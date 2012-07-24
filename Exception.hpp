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

#include <exception>
#include <string>

#ifndef MY_EXCEPTION_H__38127386137812997458738912379364871937
#define MY_EXCEPTION_H__38127386137812997458738912379364871937

/**
 * Class Exception representing the exception in application.
 */
class Exception : public std::exception
{
    private:
        std::string m_msg;      /** String containing the error message of exception. */

    public:
        Exception();
        Exception(const std::string& msg);
        virtual ~Exception() throw() { }
        virtual const char* what() const throw();
        virtual std::string getMessage() const;
        virtual std::string toString() const;
};

#endif /* MY_EXCEPTION_H__38127386137812997458738912379364871937 */