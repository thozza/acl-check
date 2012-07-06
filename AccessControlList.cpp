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

#include "AccessControlList.hpp"

using namespace std;

/**
 * Class constructor.
 *
 * @param id string containing name (ID) of an ACL.
 */
AccessControlList::AccessControlList(const string id) : m_aclID(id) { }

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
AccessControlList::~AccessControlList() { }

//-----------------------------------------------------------------------------------

/**
 * Method for adding new rule on the end of the ACL.
 *
 * Method adds new rule on the end of the ACL if passed pointer is not NULL.
 *
 * @param newRule pointer to the new rule we want to add to the ACL.
 */
void AccessControlList::pushBack(AclRule* newRule)
{
    if ( newRule != NULL )
    {
        m_rulesVector.push_back(newRule);
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting name (ID) of the ACL.
 *
 * Method returns string containing name (ID) of the ACL.
 *
 * @return string containing name (ID) of the ACL.
 */
string AccessControlList::name() const
{
    return m_aclID;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting size of the ACL.
 *
 * Method returns size (number of rules) of the ACL.
 *
 * @return size (number of rules) of the ACL.
 */
size_t AccessControlList::size() const
{
    return m_rulesVector.size();
}

//-----------------------------------------------------------------------------------

/**
 * Operator [] used for accessing rule reference on the given index.
 *
 * Operator returns reference to the rule on the given index.
 * Returned reference is NOT constant, therefore it can be used for modifying accessed rule.
 * If there is no rule in ACL with the given index, operator throws an exception "Index out of borders!".
 *
 * @throw Exception operator throws an exception "Index out of borders!" if there is no rule in ACL with
 *                  the given index.
 * @param n index of the rule we want to access. It should be value between "0" and "size() - 1".
 * @return reference to the rule on the given index.
 */
AclRule& AccessControlList::operator[](size_t n) throw(Exception)
{
    if ( n < m_rulesVector.size() )
        return m_rulesVector[n];
    else
        throw Exception("Index out of borders!");
}

//-----------------------------------------------------------------------------------

/**
 * Operator [] used for accessing rule constant reference on the given index.
 *
 * Operator returns constant reference to the rule on the given index.
 * Returned reference IS constant, therefore it can NOT be used for modifying accessed rule.
 * If there is no rule in ACL with the given index, operator throws an exception "Index out of borders!".
 *
 * @throw Exception operator throws an exception "Index out of borders!" if there is no rule in ACL with
 *                  the given index.
 * @param n index of the rule we want to access. It should be value between "0" and "size() - 1".
 * @return reference to the rule on the given index.
 */
const AclRule& AccessControlList::operator[](size_t n) const throw(Exception)
{
    if ( n < m_rulesVector.size() )
        return m_rulesVector[n];
    else
        throw Exception("Index out of borders!");
}

//-----------------------------------------------------------------------------------

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
ostream& operator<<(std::ostream& out, const AccessControlList& acl)
{
    out << "Access Control List ID=\"" << acl.name() << "\" with [" << acl.size() << "] rules" << endl;
    out << "-------------------------------------------------------------" << endl;

    size_t numOfRules = acl.size();

    for ( size_t i = 0; i < numOfRules; ++i )
    {
        out << acl[i].getName() << ".\t" << acl[i] << endl;
    }

    return out;
}