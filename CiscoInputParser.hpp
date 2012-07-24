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

#include <map>
#include <memory>
#include <sys/types.h>

#include "AclRule.hpp"
#include "InputParser.hpp"

#ifndef CISCO_INPUTPARSER_HPP__563783712536778984765487984387687179468452747276463790
#define CISCO_INPUTPARSER_HPP__563783712536778984765487984387687179468452747276463790

#ifndef HP_CISCO_CMNDS__5315314354
#define HP_CISCO_CMNDS__5315314354

/**
 * Constant representing error.
 */
const int ERROR_FLAG = -1;

/*
 * Constants representing type of parsed command.
 */
const int CMD_MISC = 0;
const int CMD_ACCESS_LIST = 1;
const int CMD_IP_ACCESS_LIST = 2;
const int CMD_IP_ACCESS_LIST_RULE = 3;
const int CMD_ACL_RULE_REMARK = 4;

/*
 * Constants representing type of ACL.
 */
const int ACL_STANDARD = 0;
const int ACL_EXTENDED = 1;

#endif /* HP_CISCO_CMNDS__5315314354 */

/**
 * Class CiscoInputParser represents input parser of Cisco configuration file.
 *
 * Class provides only one public method parse() which is used to parse Cisco
 * configuration entered as an input data stream std::istream. Method output
 * is smart pointer to vector containing all parsed ACLs from configuration.
 */
class CiscoInputParser : public InputParser
{
    protected:
        std::map< std::string, AccessControlList* > m_aclsByName;               /** Map used to access existing ACLs by their name (ID). */
        std::auto_ptr< boost::ptr_vector< AccessControlList > > m_aclsVector;   /** Vector containing parsed ACLs. */

        AccessControlList* getAclByName(int name);
        AccessControlList* getAclByName(const std::string& name);
        AccessControlList* createNewAcl(const std::string& name);
        
        /*********************** STATIC METHODS ***********************/
        static std::auto_ptr< AclRule > handleAccessList(int number, unsigned position, const char* str);
        static std::auto_ptr< AclRule > handleStandardRule(unsigned position, const char* str);
        static std::auto_ptr< AclRule > handleExtendedRule(unsigned position, const char* str);
        
        static int resolveAccessListType(int number);
        static int resolveAccessListType(const char* str, unsigned& charsExtracted);
        static int parseAccessListNumber(const char* str, unsigned& charsExtracted);
        static std::string parseAccessListName(const char* str);

        static int parseCommand(const char* str, unsigned& charsExtracted);

        static int parseAction(const char* str, unsigned& charsExtracted);

        static int parseProtocol(const char* str, unsigned& charsExtracted);
        static int parseProtocolByNum(const char* str, unsigned& charsExtracted);

        static int parsePort(const char* str, unsigned& charsExtracted, u_int16_t& portStart, u_int16_t& portStop, bool& portNeg);
        static u_int16_t parsePortByNum(const char* str, unsigned& charsExtracted);
        static u_int16_t parsePortByName(const char* str, unsigned& charsExtracted);

        static void parseAddrAndWildcard(const char* str, IP_ADDRESS& addr, IP_ADDRESS& wildC, unsigned& charsExtracted);
        static IP_ADDRESS parseIPv4addr(const char* str);
        static IP_ADDRESS ipV4WildcardToMask(const IP_ADDRESS& wildcard);
        static void fillIPv4Range(const IP_ADDRESS& addr, const IP_ADDRESS& wildc, IP_ADDRESS& range_start, IP_ADDRESS& range_stop);

        static void skipWhiteChars(const char* str, unsigned& charsExtracted);
        static void rollbackStream(std::istream& stream, std::streamsize size);
        static std::string commandToString(int cmd);
        
    public:
        CiscoInputParser() { };
        virtual ~CiscoInputParser() { };
        virtual std::auto_ptr< boost::ptr_vector< AccessControlList > > parse(std::istream& inputStream);
};

#endif /* CISCO_INPUTPARSER_HPP__563783712536778984765487984387687179468452747276463790 */