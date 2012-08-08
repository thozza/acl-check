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

#include <sstream>
#include "rapidxml/rapidxml_print.hpp"

#include "XmlOutputWriter.hpp"
#include "Exception.hpp"

using namespace std;
using namespace rapidxml;

/**
 * Class constructor.
 *
 * @param outputStream reference to the output stream to which the final XML document will be written.
 * @param outputDetail value representing output data detail level (constant OUTPUT_DETAIL_X).
 */
XmlOutputWriter::XmlOutputWriter(std::ostream& outputStream, int outputDetail): OutputWriter(outputStream, outputDetail), m_curentAcl(NULL), m_analysisDoc(NULL)
{
    /* create the XML header */
    xml_node< >* declaration = m_xmlDoc.allocate_node(node_declaration);
    declaration->append_attribute(m_xmlDoc.allocate_attribute("version", "1.0"));
    declaration->append_attribute(m_xmlDoc.allocate_attribute("encoding", "utf-8"));
    m_xmlDoc.append_node(declaration);
    m_analysisDoc = newNode("AclCheck-analysis");
    m_analysisDoc->append_attribute(newAttribute("output-detail", newString(outDetailToString())));
    m_xmlDoc.append_node(m_analysisDoc);
}

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
XmlOutputWriter::~XmlOutputWriter()
{
    /* free the memory used for XML document */
    m_xmlDoc.clear();
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new node with given name.
 *
 * @param name pointer to the string containing name of new node.
 * @return pointer to the new allocated node with given name.
 */
xml_node< >* XmlOutputWriter::newNode(const char* name)
{
    return m_xmlDoc.allocate_node(node_element, newString(name));
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new attribute of a node with given value.
 *
 * @param name pointer to the string containing name of new attribute.
 * @param value numeric value representing the new attribute value.
 * @return pointer to the new allocated attribute with given values.
 */
xml_attribute< char >* XmlOutputWriter::newAttribute(const char* name, unsigned value)
{
    return m_xmlDoc.allocate_attribute(newString(name), newString(value));
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new attribute of a node with given value.
 *
 * @param name pointer to the string containing name of new attribute.
 * @param value pointer to the string representing the new attribute value.
 * @return pointer to the new allocated attribute with given values.
 */
xml_attribute< >* XmlOutputWriter::newAttribute(const char* name, const char* value)
{
    return m_xmlDoc.allocate_attribute(newString(name), newString(value));
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new attribute of a node with given value.
 *
 * @param name pointer to the string containing name of new attribute.
 * @param value string representing the new attribute value.
 * @return pointer to the new allocated attribute with given values.
 */
xml_attribute< >* XmlOutputWriter::newAttribute(const char* name, const std::string value)
{
    return m_xmlDoc.allocate_attribute(newString(name), newString(value));
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new string with given value.
 *
 * @param value numeric value for which new string will be allocated.
 * @return pointer to the new allocated string.
 */
char* XmlOutputWriter::newString(unsigned value)
{
    stringstream ss;
    ss << value;
    
    return newString(ss.str());
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new string with given value.
 *
 * @param value pointer to a string for which new string will be allocated.
 * @return pointer to the new allocated string.
 */
char* XmlOutputWriter::newString(const char* value)
{
    return m_xmlDoc.allocate_string(value);
}

//-----------------------------------------------------------------------------------

/**
 * Method allocates new string with given value.
 *
 * @param value reference to a string for which new string will be allocated.
 * @return pointer to the new allocated string.
 */
char* XmlOutputWriter::newString(const std::string& value)
{
    return m_xmlDoc.allocate_string(value.c_str());
}

//-----------------------------------------------------------------------------------

/**
 * Method converting seted detail value to a string.
 *
 * @return string containing numeric value representing the data detail level.
 */
string XmlOutputWriter::outDetailToString()
{
    switch ( m_outputDetail )
    {
        case OUTPUT_DETAIL_1:
            return "1";
            
        case OUTPUT_DETAIL_2:
            return "2";
            
        case OUTPUT_DETAIL_3:
            return "3";
            
        case OUTPUT_DETAIL_4:
            return "4";
            
        default:
            return "unknown";
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing new conflict for the actual ACL.
 *
 * Method writes analysis data with OUTPUT_DETAIL_1.
 *
 * @param confl reference to the object representing the conflict.
 */
void XmlOutputWriter::writeNewConflictLvl1(const Conflict& confl)
{
    xml_node< > *newConflNode = newNode("conflict");
    newConflNode->append_attribute(newAttribute("type", confl.conflictTypeStr()));
    m_curentAcl->append_node(newConflNode);

    const AclRule& ruleX = confl.getRuleXRef();
    xml_node< > *tmpNode = newNode("ruleX");
    tmpNode->append_attribute(newAttribute("name", newString(ruleX.getName())));
    newConflNode->append_node(tmpNode);

    const AclRule& ruleY = confl.getRuleYRef();
    tmpNode = newNode("ruleY");
    tmpNode->append_attribute(newAttribute("name", newString(ruleY.getName())));
    newConflNode->append_node(tmpNode);
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing new conflict for the actual ACL.
 *
 * Method writes analysis data with OUTPUT_DETAIL_2.
 *
 * @param confl reference to the object representing the conflict.
 */
void XmlOutputWriter::writeNewConflictLvl2(const Conflict& confl)
{
    xml_node< > *newConflNode = newNode("conflict");
    newConflNode->append_attribute(newAttribute("type", confl.conflictTypeStr()));
    m_curentAcl->append_node(newConflNode);

    const AclRule& ruleX = confl.getRuleXRef();
    xml_node< > *tmpNode = newNode("ruleX");
    tmpNode->append_attribute(newAttribute("name", newString(ruleX.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleX.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleX.getSrcIpRangeString())));
    tmpNode->append_attribute(newAttribute("action", newString(ruleX.getActionString())));
    newConflNode->append_node(tmpNode);

    const AclRule& ruleY = confl.getRuleYRef();
    tmpNode = newNode("ruleY");
    tmpNode->append_attribute(newAttribute("name", newString(ruleY.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleY.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleY.getSrcIpRangeString())));
    tmpNode->append_attribute(newAttribute("action", newString(ruleY.getActionString())));
    newConflNode->append_node(tmpNode);
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing new conflict for the actual ACL.
 *
 * Method writes analysis data with OUTPUT_DETAIL_3.
 *
 * @param confl reference to the object representing the conflict.
 */
void XmlOutputWriter::writeNewConflictLvl3(const Conflict& confl)
{
    xml_node< > *newConflNode = newNode("conflict");
    newConflNode->append_attribute(newAttribute("type", confl.conflictTypeStr()));
    m_curentAcl->append_node(newConflNode);

    const AclRule& ruleX = confl.getRuleXRef();
    xml_node< > *tmpNode = newNode("ruleX");
    tmpNode->append_attribute(newAttribute("name", newString(ruleX.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleX.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleX.getSrcIpRangeString())));
    if ( (ruleX.getProtocol() == PROTO_TCP) || (ruleX.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("srcPort", newString(ruleX.getSrcPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("dstIP", newString(ruleX.getDstIpRangeString())));
    if ( (ruleX.getProtocol() == PROTO_TCP) || (ruleX.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("dstPort", newString(ruleX.getDstPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("action", newString(ruleX.getActionString())));
    newConflNode->append_node(tmpNode);

    const AclRule& ruleY = confl.getRuleYRef();
    tmpNode = newNode("ruleY");
    tmpNode->append_attribute(newAttribute("name", newString(ruleY.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleY.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleY.getSrcIpRangeString())));
    if ( (ruleY.getProtocol() == PROTO_TCP) || (ruleY.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("srcPort", newString(ruleY.getSrcPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("dstIP", newString(ruleY.getDstIpRangeString())));
    if ( (ruleY.getProtocol() == PROTO_TCP) || (ruleY.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("dstPort", newString(ruleY.getDstPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("action", newString(ruleY.getActionString())));
    newConflNode->append_node(tmpNode);
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing new conflict for the actual ACL.
 *
 * Method writes analysis data with OUTPUT_DETAIL_4.
 *
 * @param confl reference to the object representing the conflict.
 */
void XmlOutputWriter::writeNewConflictLvl4(const Conflict& confl)
{
    xml_node< > *newConflNode = newNode("conflict");
    newConflNode->append_attribute(newAttribute("type", confl.conflictTypeStr()));
    m_curentAcl->append_node(newConflNode);

    const AclRule& ruleX = confl.getRuleXRef();
    xml_node< > *tmpNode = newNode("ruleX");
    tmpNode->append_attribute(newAttribute("name", newString(ruleX.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleX.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleX.getSrcIpRangeString())));
    if ( (ruleX.getProtocol() == PROTO_TCP) || (ruleX.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("srcPort", newString(ruleX.getSrcPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("dstIP", newString(ruleX.getDstIpRangeString())));
    if ( (ruleX.getProtocol() == PROTO_TCP) || (ruleX.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("dstPort", newString(ruleX.getDstPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("action", newString(ruleX.getActionString())));
    newConflNode->append_node(tmpNode);

    const AclRule& ruleY = confl.getRuleYRef();
    tmpNode = newNode("ruleY");
    tmpNode->append_attribute(newAttribute("name", newString(ruleY.getName())));
    tmpNode->append_attribute(newAttribute("proto", newString(ruleY.getProtocolString())));
    tmpNode->append_attribute(newAttribute("srcIP", newString(ruleY.getSrcIpRangeString())));
    if ( (ruleY.getProtocol() == PROTO_TCP) || (ruleY.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("srcPort", newString(ruleY.getSrcPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("dstIP", newString(ruleY.getDstIpRangeString())));
    if ( (ruleY.getProtocol() == PROTO_TCP) || (ruleY.getProtocol() == PROTO_UDP) )
    {
        tmpNode->append_attribute(newAttribute("dstPort", newString(ruleY.getDstPortRangeString())));
    }
    tmpNode->append_attribute(newAttribute("action", newString(ruleY.getActionString())));
    newConflNode->append_node(tmpNode);

    tmpNode = newNode("relation");
    tmpNode->append_attribute(newAttribute("proto", newString(Conflict::relationTypeToString(confl.getDimensionsRelation(DIMENSION_PROTO)))));
    tmpNode->append_attribute(newAttribute("srcIP", newString(Conflict::relationTypeToString(confl.getDimensionsRelation(DIMENSION_SRC_IP)))));
    tmpNode->append_attribute(newAttribute("srcPort", newString(Conflict::relationTypeToString(confl.getDimensionsRelation(DIMENSION_SRC_PRT)))));
    tmpNode->append_attribute(newAttribute("dstIP", newString(Conflict::relationTypeToString(confl.getDimensionsRelation(DIMENSION_DST_IP)))));
    tmpNode->append_attribute(newAttribute("dstPort", newString(Conflict::relationTypeToString(confl.getDimensionsRelation(DIMENSION_DST_PRT)))));
    newConflNode->append_node(tmpNode);
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing a new ACL with given name (ID).
 *
 * Newly added ACL becomes the actual ACL, under which are the
 * following new conflicts added.
 *
 * @param aclID reference to a string containing name (ID) of the ACL.
 */
void XmlOutputWriter::writeNewACL(std::string aclID)
{
    m_curentAcl = newNode("access-list");
    m_curentAcl->append_attribute(newAttribute("id", aclID));
    m_analysisDoc->append_node(m_curentAcl);
}

//-----------------------------------------------------------------------------------

/**
 * Method for writing new conflict under the actual ACL.
 *
 * Method depending on choosen detail level calls appropriate
 * method for writing conflict data to the XML document.
 *
 * @param confl reference to the object containing conflict data.
 */
void XmlOutputWriter::writeNewConflict(const Conflict& confl)
{
    if ( m_curentAcl == NULL)
        writeNewACL("no-id");

    switch ( m_outputDetail )
    {
        case OUTPUT_DETAIL_1:
            writeNewConflictLvl1(confl);
            return;

        case OUTPUT_DETAIL_2:
            writeNewConflictLvl2(confl);
            return;

        case OUTPUT_DETAIL_3:
            writeNewConflictLvl3(confl);
            return;

        case OUTPUT_DETAIL_4:
            writeNewConflictLvl4(confl);
            return;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method which writes the created XML document to the output stream given in constructor.
 */
void XmlOutputWriter::flush()
{
     m_outStream << m_xmlDoc;
}