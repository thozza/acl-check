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

#include "PrefixForest.hpp"
#include "GlobalDefs.hpp"

using namespace std;

/**
 * Class constructor.
 *
 * Class constructor that creates the object of the forest of prefix tress that contains as many trees as
 * the passed number of dimensions of rules numOfDimensions. Created trees can be used
 * only for ACL with passed number of rules.
 *
 * @param aclSize unsigned value representing the number of rules in ACL
 *                for which the forest of prefix trees is created.
 * @param numOfDimensions umber of dimensions of rules which are in ACL.
 *                        Default value is DIMENSION_MAX + 1 (as the dimensions are numbered from "0").
 */
PrefixForest::PrefixForest(u_int32_t aclSize, int numOfDimensions) : m_numOfAclRules(aclSize), m_numOfRuleDimensions(numOfDimensions)
{
    /* create prefix trees */
    for ( int i = DIMENSION_MIN; i < numOfDimensions; ++i )
    {
        m_triesVector.push_back(new PrefixTree(aclSize));
    }
}

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
PrefixForest::~PrefixForest() { }

//-----------------------------------------------------------------------------------

/**
 * Method for adding new rule to prefix forest.
 *
 * Method adds passed rule to the forest of prefix trees. It returns the object auto_ptr containing the pointer
 * to conflict bit vector of type WAHBitVector for passed rule. Conflict bit vector has
 * set value "1" at the position "i", if there is a rule in ACL at position "i", that
 * is in the conflict with passed rule and the rule "i" is already in the prefix forest.
 * The conflict is determined by dimensions of rules in prefix format.
 *
 * @param rule reference to the object AclRule to be added to the forest
 * @return object auto_ptr containing the pointer to the conflict bit vector of type WAHBitVector
 *         for passed rule 
 */
auto_ptr< WAHBitVector > PrefixForest::addAclRule(const AclRule& rule)
{
    auto_ptr< WAHBitVector > conflictsVector(new WAHBitVector(m_numOfAclRules, true));

    unsigned tmp_rulePosition = rule.getPosition();
    for ( int i = DIMENSION_MIN; i < m_numOfRuleDimensions; ++i )
    {
        *conflictsVector &= *(m_triesVector[i].addNewRulePrefix(rule.getFieldPrefix(i), tmp_rulePosition));
    }

    return conflictsVector;
}