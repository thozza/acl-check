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
#include <string>

#include "AclRule.hpp"
#include "Exception.hpp"

#ifndef ACCESSCONTROLLIST_H__7382638678465165168144735416181313461
#define ACCESSCONTROLLIST_H__7382638678465165168144735416181313461

/**
 * Class AccessControlList represents a Access Control List.
 *
 * Class represents particular Access Control List with a name and
 * a specific set of rules. It provides interface for accessing rules,
 * adding new rules and for getting specific parameters of the ACL.
 */
class AccessControlList
{
    private:
        boost::ptr_vector<AclRule> m_rulesVector;       /** Vector of pointers to objects representing ACL rules. */
        std::string m_aclID;                            /** String containing name or ID of the ACL. */

    public:
        AccessControlList(const std::string id = "no-ID");
        virtual ~AccessControlList();

        void pushBack(AclRule* newRule);
        std::string name() const;
        size_t size() const;

        AclRule& operator[](size_t n) throw(Exception);
        const AclRule& operator[](size_t n) const throw(Exception);

        /**
         * Operator << used for printing information about the ACL and its rules to the given output stream (std::ostream).
         *
         * Operator prints information about the ACL and its rules to the given output stream in following format:
         * 'Access Control List ID="NAME/ID" with [NUMBER] rules'
         * '-------------------------------------------------------------'
         * 'POSITION/NAME.   "AclRule OUTPUT FORMAT"'
         * '...'
         *
         * @param out reference to the output stream.
         * @param acl reference to constant object of the ACL.
         * @return reference to the output stream, that was given previously as a parameter.
         */
        friend std::ostream& operator<<(std::ostream& out, const AccessControlList& acl);
};

#endif /* ACCESSCONTROLLIST_H__7382638678465165168144735416181313461 */