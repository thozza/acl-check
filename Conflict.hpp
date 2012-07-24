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

#include <memory>
#include <vector>

#include "AclRule.hpp"

#ifndef CONFLICT_HPP__6812754861346416844215346816484615848341862843847213845
#define CONFLICT_HPP__6812754861346416844215346816484615848341862843847213845

/*
 * Constants representing the type of the error between the pair of rules.
 */
const int CONFLICT_NONE = 0;
const int CONFLICT_REDUNDANCY = 1;
const int CONFLICT_SHADOWING = 2;
const int CONFLICT_GENERALIZATION = 3;
const int CONFLICT_SUPERIMPOSING = 4;
const int CONFLICT_CORELATION = 5;

/*
 * Constants reresenting the relation between the sets, or the values
 * (if the relation is meaningful for given pair).
 */
const int RELATION_NONE = 0;                    /** Values/sets are different. */
const int RELATION_1_SUPERSET_2 = 1;            /** Set 1 is the superset of the set 2. */
const int RELATION_1_SUBSET_2 = 2;              /** Set 1 is the subset of the set 2. */
const int RELATION_1_EQUIV_2 = 3;               /** Values/sets are equal. */
const int RELATION_1_INTERLEAVING_2 = 4;        /** Sets 1 and 2 are interleaving. */

const int RELATION_1_BIGGER_2 = 5;
const int RELATION_1_SMALLER_2 = 6;

/**
 * The class representing the result of the conflict analysis between the pair of AclRule rules.
 */
class Conflict
{
    private:
        int m_conflictType;             /** Variable with value representing the type of the conflict. */
        bool m_isConflict;              /** Flag set if there is a conflict between the pair of rules. */
        int m_dimensionsRelation[5];    /** Array containing relations between dimensions of the ACL rule. */
        const AclRule& m_ruleX;         /** Reference to rule X. */
        const AclRule& m_ruleY;         /** Reference to rule Y. */
        
    protected:
        void setConflictType(int type);
        void setDimensionRelation(int dimension, int relation);

    public:
        Conflict(const AclRule& ruleX, const AclRule& ruleY);
        virtual ~Conflict();

        int conflictType() const;
        std::string conflictTypeStr() const;
        bool isConflict() const;
        const AclRule& getRuleXRef() const;
        const AclRule& getRuleYRef() const;
        int getDimensionsRelation(int dimension) const throw(Exception);
        
        static std::auto_ptr< Conflict > classifyConflict(const AclRule& ruleX, const AclRule& ruleY);

        /********* STATIC methods *********/
        static void classifyByRange(Conflict& newObject, const AclRule& ruleX, const AclRule& ruleY);
//        static void classifyByPrefix(Conflict& newObject, const AclRule& ruleX, const AclRule& ruleY);

        static int compareTwoIPv4Addr(const IP_ADDRESS& addr1, const IP_ADDRESS& addr2);
        static int compareTwoIpv4Ranges(const IP_ADDRESS& addr1_start, const IP_ADDRESS& addr1_stop, const IP_ADDRESS& addr2_start, const IP_ADDRESS& addr2_stop);
        static int compareTwoPortValues(u_int16_t port1, u_int16_t port2);
        static int compareTwoPortRanges(u_int16_t port1_start, u_int16_t port1_stop, u_int16_t port2_start, u_int16_t port2_stop);
        static int compareTwoPortRanges(u_int16_t port1_start, u_int16_t port1_stop, bool port1_neg, u_int16_t port2_start, u_int16_t port2_stop, bool port2_neg);
        static int compareProtocol(int protocol1, int protocol2);
        static int combineRelations(int globalRelation, int partialRelation);
        static int resolveConflictType(int rule_Y_and_X_relation, int ruleYaction, int ruleXaction);

        static std::string conflictTypeToString(int type);
        static std::string relationTypeToString(int type);
};

#endif /* CONFLICT_HPP__6812754861346416844215346816484615848341862843847213845 */