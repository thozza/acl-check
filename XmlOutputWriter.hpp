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
#include "OutputWriter.hpp"

#ifndef XML_OUTPUTWRITER_HPP__4579067024396705956984357690437857583979582900698769
#define XML_OUTPUTWRITER_HPP__4579067024396705956984357690437857583979582900698769

class XmlOutputWriter : public OutputWriter
{
    protected:
        rapidxml::xml_document< > m_xmlDoc;     /** XML document object, using which we allocate other structures. */
        rapidxml::xml_node< >* m_curentAcl;     /** Pointer to the node of actual ACL. */
        rapidxml::xml_node< >* m_analysisDoc;   /** Pointer to the node representing final output document for all ACLs. */

        rapidxml::xml_node< >* newNode(const char* name = 0);
        rapidxml::xml_attribute< >* newAttribute(const char* name = 0, unsigned value = 0);
        rapidxml::xml_attribute< >* newAttribute(const char* name = 0, const char* value = 0);
        rapidxml::xml_attribute< >* newAttribute(const char* name = 0, const std::string value = "");
        char* newString(unsigned value);
        char* newString(const char* value = 0);
        char* newString(const std::string& value);

        std::string outDetailToString();

        void writeNewConflictLvl1(const Conflict& confl);
        void writeNewConflictLvl2(const Conflict& confl);
        void writeNewConflictLvl3(const Conflict& confl);
        void writeNewConflictLvl4(const Conflict& confl);
        
    public:
        XmlOutputWriter(std::ostream& outputStream, int outputDetail = OUTPUT_DETAIL_2);
        virtual ~XmlOutputWriter();

        virtual void writeNewACL(std::string aclID);
        virtual void writeNewConflict(const Conflict& confl);
        virtual void flush();
};

#endif /* XML_OUTPUTWRITER_HPP__4579067024396705956984357690437857583979582900698769 */