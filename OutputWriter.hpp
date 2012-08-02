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

#include <ostream>

#include "Conflict.hpp"

#ifndef OUTPUT_WRITER_HPP__567587456974368967234576890582723698779857494387
#define OUTPUT_WRITER_HPP__567587456974368967234576890582723698779857494387

/*
 * Constants defining the detail level of output analysis.
 *
 * Content of levels:
 * OUTPUT_DETAIL_1 - the error type, for both rules - rule position.
 * OUTPUT_DETAIL_2 - the error type, for both rules - rule position, protocol, source IP, action.
 * OUTPUT_DETAIL_3 - the error type, for both rules - rule position, protocol, source IP, source port, destination IP, destination port, action.
 * OUTPUT_DETAIL_4 - the error type, vztahy jednotlivych poli pravidiel, for both rules - rule position, protocol, source IP, source port, destination IP, destination port, action.
 */
const int OUTPUT_DETAIL_1 = 1;
const int OUTPUT_DETAIL_2 = 2;
const int OUTPUT_DETAIL_3 = 3;
const int OUTPUT_DETAIL_4 = 4;

class OutputWriter
{
    protected:
        std::ostream& m_outStream;      /** Reference to output stream std::ostream. */
        const int m_outputDetail;       /** The value representing the detail level on output. */
        
    public:
        OutputWriter(std::ostream& outputStream, int outputDetail = OUTPUT_DETAIL_2) : m_outStream(outputStream), m_outputDetail(outputDetail) { };
        virtual ~OutputWriter() { };

        virtual void writeNewACL(std::string aclID) = 0;
        virtual void writeNewConflict(const Conflict& confl) = 0;
        virtual void flush() = 0;
};

#endif /* OUTPUT_WRITER_HPP__567587456974368967234576890582723698779857494387 */