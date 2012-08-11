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

#include <iostream>

#include "Conflict.hpp"
#include "GlobalDefs.hpp"

using namespace std;

/**
 * Class constructor.
 *
 * @param ruleX reference to rule X (first in the pair).
 * @param ruleY reference to rule Y (second in the pair).
 */
Conflict::Conflict(const AclRule& ruleX, const AclRule& ruleY) : m_conflictType(CONFLICT_NONE),
                                                                 m_isConflict(false),
                                                                 m_ruleX(ruleX),
                                                                 m_ruleY(ruleY)
{
    m_dimensionsRelation[0] = RELATION_NONE;
    m_dimensionsRelation[1] = RELATION_NONE;
    m_dimensionsRelation[2] = RELATION_NONE;
    m_dimensionsRelation[3] = RELATION_NONE;
    m_dimensionsRelation[4] = RELATION_NONE;
}

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
Conflict::~Conflict() { }

//-----------------------------------------------------------------------------------

/**
 * Methods sets passed type of the conflict and according to the value also the flag whether the conflict exists.
 *
 * @param type value representing the type of the conflict (constant CONFLICT_XXX).
 */
void Conflict::setConflictType(int type)
{
    if ( type == CONFLICT_NONE )
    {
        m_conflictType = type;
        m_isConflict = false;
    }
    else
    {
        m_conflictType = type;
        m_isConflict = true;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method returs the reference to rule X (first in the pair of analyzed rules).
 *
 * @return reference to constant object ACL rule.
 */
const AclRule& Conflict::getRuleXRef() const
{
    return m_ruleX;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the reference to rule Y (second in the pair of analyzed rules).
 *
 * @return reference to constant object ACL rule.
 */
const AclRule& Conflict::getRuleYRef() const
{
    return m_ruleY;
}

//-----------------------------------------------------------------------------------

/**
 * Method sets passed relation between the rules in passed dimension of the rule.
 *
 * @throw Exception if the passed dimension is not known, method throws
 *                  an exception "Unknown dimension! Out of borders!".
 * @param dimension dimension in which the relation is set (constant DIMENSION_XXX).
 * @param relation relation (constant RELATION_XXX) between the rules in passed dimension.
 */
void Conflict::setDimensionRelation(int dimension, int relation)
{
    if ( (dimension > DIMENSION_MAX) || (dimension < DIMENSION_MIN) )
        throw Exception("Unknown dimension! Out of borders!");
    else
        m_dimensionsRelation[dimension] = relation;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns numerical value representing the type of the conflict.
 *
 * @return numerical value representing the type of the conflict (CONFLICT_XXX).
 */
int Conflict::conflictType() const
{
    return m_conflictType;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns a string representing the type of the conflict.
 *
 * @return string representing the type of the conflict.
 */
string Conflict::conflictTypeStr() const
{
    return conflictTypeToString(m_conflictType);
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the flag set if the conflict is there.
 *
 * @return TRUE - there is a conflict between the rules.
 *         FALSE - there is not a conflict between the rules.
 */
bool Conflict::isConflict() const
{
    return m_isConflict;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the numerical value representing the relation between rules in passed dimension.
 *
 * @throw Exception if the passed dimension is not known, method throws
 *                  an exception "Unknown dimension! Out of borders!".
 * @param dimension dimension in which the relation is returned (constant DIMENSION_XXX).
 * @return numerical value representing the relation between dimension of rules (constant RELATION_XXX).
 */
int Conflict::getDimensionsRelation(int dimension) const throw(Exception)
{
    if ( (dimension > DIMENSION_MAX) || (dimension < DIMENSION_MIN) )
        throw Exception("Unknown dimension! Out of borders!");
    else
        return m_dimensionsRelation[dimension];
}

//-----------------------------------------------------------------------------------

/**
 * Method classifies conflict between passed rules.
 *
 * Method classifies the conflict between two passed rules
 * ruleX a ruleY. Method returns smart pointer containing pointer to
 * object of the class Conflict containing information about the analysis and about the conflict.
 * Method classifies conflict according to ranges, but it is suitable to
 * add classification according to prefixes. Classification according to
 * prefixes has not been implemented, as it was not necessary for tool's functioning.
 *
 * @param ruleX reference to object AclRule containing information about X ACL rule.
 * @param ruleY reference to object AclRule containing information about Y ACL rule.
 * @return smart pointer containing pointer to object of class Conflict containing information about the analysis.
 */
auto_ptr< Conflict > Conflict::classifyConflict(const AclRule& ruleX, const AclRule& ruleY)
{
//     if ( classifyBy == CLASSIFY_BY_RANGE )
//     {
        auto_ptr< Conflict > confObject(new Conflict(ruleX, ruleY));
        classifyByRange(*confObject, ruleX, ruleY);

        return confObject;
//     }
//     else if ( classifyBy == CLASSIFY_BY_PREFIX )
//     {
//         throw Exception("ERROR-Conflict: Classifycation by prefix is not implemented yet!");
//     }
//     else
//         throw Exception("ERROR-Conflict: Unknown classifycation method chosed!");
}

//-----------------------------------------------------------------------------------

/**
 * Method classifies conflict between passed rules accordin to ranges.
 *
 * Method classifies conflict between dvoma passed rules
 * ruleX a ruleY. Method classifies conflict according to ranges.
 *
 * @param newObject reference to object of class Conflict where the information about analysis will be stored.
 * @param ruleX reference to object AclRule containing information about X ACL rule.
 * @param ruleY reference to object AclRule containing information about Y ACL rule.
 */
void Conflict::classifyByRange(Conflict& newObject, const AclRule& ruleX, const AclRule& ruleY)
{
    int tmp_relation = RELATION_1_EQUIV_2;

    /*************************************************************/
    /*********** analysis of the relations of all dimensions *****/

    #ifdef CONFLICT_DEBUG
    cout << "rulex#=" << ruleX.getPosition() << " " << "ruley#=" << ruleY.getPosition() << endl;
    cout << "\tstartRelation=" << relationTypeToString(tmp_relation) << endl;
    #endif
    
    /* protocols comparison */
    newObject.setDimensionRelation(DIMENSION_PROTO, compareProtocol(ruleY.getProtocol(), ruleX.getProtocol()));
    tmp_relation = combineRelations(tmp_relation, newObject.getDimensionsRelation(DIMENSION_PROTO));

    #ifdef CONFLICT_DEBUG
    cout << "\tProtocols relation=" << relationTypeToString(newObject.getDimensionsRelation(DIMENSION_PROTO)) << endl;
    cout << "\tCombined relation=" << relationTypeToString(tmp_relation) << endl << endl;
    #endif

    /* comparison of source IPv4 addresses's ranges */
    newObject.setDimensionRelation(DIMENSION_SRC_IP, compareTwoIpv4Ranges(ruleY.getSrcIpStart(), ruleY.getSrcIpStop(), ruleX.getSrcIpStart(), ruleX.getSrcIpStop()));
    tmp_relation = combineRelations(tmp_relation, newObject.getDimensionsRelation(DIMENSION_SRC_IP));

    #ifdef CONFLICT_DEBUG
    cout << "\tSRC IP relation=" << relationTypeToString(newObject.getDimensionsRelation(DIMENSION_SRC_IP)) << endl;
    cout << "\tCombined relation=" << relationTypeToString(tmp_relation) << endl << endl;
    #endif

    /* comparison of destination IPv4 addresses ranges */
    newObject.setDimensionRelation(DIMENSION_DST_IP, compareTwoIpv4Ranges(ruleY.getDstIpStart(), ruleY.getDstIpStop(), ruleX.getDstIpStart(), ruleX.getDstIpStop()));
    tmp_relation = combineRelations(tmp_relation, newObject.getDimensionsRelation(DIMENSION_DST_IP));

    #ifdef CONFLICT_DEBUG
    cout << "\tDST IP relation=" << relationTypeToString(newObject.getDimensionsRelation(DIMENSION_DST_IP)) << endl;
    cout << "\tCombined relation=" << relationTypeToString(tmp_relation) << endl << endl;
    #endif

    /* comparison of source ports ranges */
    newObject.setDimensionRelation(DIMENSION_SRC_PRT, compareTwoPortRanges(ruleY.getSrcPortStart(), ruleY.getSrcPortStop(), ruleY.getSrcPortNeg(), ruleX.getSrcPortStart(), ruleX.getSrcPortStop(), ruleX.getSrcPortNeg()));
    tmp_relation = combineRelations(tmp_relation, newObject.getDimensionsRelation(DIMENSION_SRC_PRT));

    #ifdef CONFLICT_DEBUG
    cout << "\tSRC port relation=" << relationTypeToString(newObject.getDimensionsRelation(DIMENSION_SRC_PRT)) << endl;
    cout << "\tCombined relation=" << relationTypeToString(tmp_relation) << endl << endl;
    #endif

    /* comparison of destination ports ranges */
    newObject.setDimensionRelation(DIMENSION_DST_PRT, compareTwoPortRanges(ruleY.getDstPortStart(), ruleY.getDstPortStop(), ruleY.getDstPortNeg(), ruleX.getDstPortStart(), ruleX.getDstPortStop(), ruleX.getDstPortNeg()));
    tmp_relation = combineRelations(tmp_relation, newObject.getDimensionsRelation(DIMENSION_DST_PRT));

    #ifdef CONFLICT_DEBUG
    cout << "\tDST port relation=" << relationTypeToString(newObject.getDimensionsRelation(DIMENSION_DST_PRT)) << endl;
    cout << "\tCombined relation=" << relationTypeToString(tmp_relation) << endl << endl;
    #endif

    /* get type of the conflict */
    newObject.setConflictType(resolveConflictType(tmp_relation, ruleY.getAction(), ruleX.getAction()));
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed IPv4 addresses and returns the result of comparison.
 *
 * @param addr1 reference to structure IP_ADDRESS containing first IP address.
 * @param addr2 reference to structure IP_ADDRESS containing second IP address.
 * @return value representing relation between addr1 and addr2.
 *         if addr1 == addr2, returns value RELATION_1_EQUIV_2.
 *         if addr1 > addr2, returns value RELATION_1_BIGGER_2.
 *         if addr1 < addr2, returns value RELATION_1_SMALLER_2.
 */
int Conflict::compareTwoIPv4Addr(const IP_ADDRESS& addr1, const IP_ADDRESS& addr2)
{
    if ( *((u_int32_t* const) &addr1) == *((u_int32_t* const) &addr2) )
    {
        return RELATION_1_EQUIV_2;
    }
    else if ( *((u_int32_t* const) &addr1) > *((u_int32_t* const) &addr2) )
    {
        return RELATION_1_BIGGER_2;
    }
    else
    {
        return RELATION_1_SMALLER_2;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed ranges of IPv4 addresses and return the result of the comparison.
 *
 * @param addr1_start reference to structure IP_ADDRESS containing start address of the first range.
 * @param addr1_stop reference to structure IP_ADDRESS containing end address of the first range.
 * @param addr2_start reference to structure IP_ADDRESS containing start address of the second range.
 * @param addr2_stop reference to structure IP_ADDRESS containing end address of the second range.
 * @return value representing relation between the range addr1 (addr1_start - addr1_stop) and addr2 (addr2_start - addr2_stop).
 *         if addr1 != addr2, returns value RELATION_NONE.
 *         if addr1 == addr2, returns value RELATION_1_EQUIV_2.
 *         if addr1 is the subset of addr2, returns value RELATION_1_SUBSET_2.
 *         if addr1 is the superset of addr2, returns value RELATION_1_SUPERSET_2.
 *         if sets addr1 and addr2 are interleaving, returns value RELATION_1_INTERLEAVING_2.
 */
int Conflict::compareTwoIpv4Ranges(const IP_ADDRESS& addr1_start, const IP_ADDRESS& addr1_stop, const IP_ADDRESS& addr2_start, const IP_ADDRESS& addr2_stop)
{
    if ( (compareTwoIPv4Addr(addr1_stop, addr2_start) == RELATION_1_SMALLER_2) ||
         (compareTwoIPv4Addr(addr2_stop, addr1_start) == RELATION_1_SMALLER_2) )
    {
        return RELATION_NONE;
    }
    else if ( (compareTwoIPv4Addr(addr1_start, addr2_start) == RELATION_1_EQUIV_2) &&
              (compareTwoIPv4Addr(addr1_stop, addr2_stop) == RELATION_1_EQUIV_2) )
    {
        return RELATION_1_EQUIV_2;
    }
    else if ( ((compareTwoIPv4Addr(addr1_start, addr2_start) == RELATION_1_EQUIV_2) || (compareTwoIPv4Addr(addr1_start, addr2_start) == RELATION_1_BIGGER_2)) &&
              ((compareTwoIPv4Addr(addr1_stop, addr2_stop) == RELATION_1_EQUIV_2) || (compareTwoIPv4Addr(addr1_stop, addr2_stop) == RELATION_1_SMALLER_2)))
    {
        return RELATION_1_SUBSET_2;
    }
    else if ( ((compareTwoIPv4Addr(addr1_start, addr2_start) == RELATION_1_EQUIV_2) || (compareTwoIPv4Addr(addr1_start, addr2_start) == RELATION_1_SMALLER_2)) &&
              ((compareTwoIPv4Addr(addr1_stop, addr2_stop) == RELATION_1_EQUIV_2) || (compareTwoIPv4Addr(addr1_stop, addr2_stop) == RELATION_1_BIGGER_2)))
    {
        return RELATION_1_SUPERSET_2;
    }
    else
    {
        return RELATION_1_INTERLEAVING_2;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed ports and returns the result of the comparison.
 *
 * @param port1 value of te first port.
 * @param port2 value of the second port.
 * @return value representing relation between port1 and port2.
 *         if port1 == port2, returns value RELATION_1_EQUIV_2.
 *         if port1 > port2, returns value RELATION_1_BIGGER_2.
 *         if port1 < port2, returns value RELATION_1_SMALLER_2.
 */
int Conflict::compareTwoPortValues(u_int16_t port1, u_int16_t port2)
{
    if ( port1 == port2 )
    {
        return RELATION_1_EQUIV_2;
    }
    else if ( port1 > port2 )
    {
        return RELATION_1_BIGGER_2;
    }
    else
    {
        return RELATION_1_SMALLER_2;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed ranges of ports and returns the result of the comparison.
 *
 * @param port1_start value representing start port of the first range.
 * @param port1_stop value representing end port of the first range.
 * @param port2_start value representing start port of the second range.
 * @param port2_stop value representing end port of the second range.
 * @return value representing relation between port1 (port1_start - port1_stop) and port2 (port2_start - port2_stop).
 *         if port1 != port2, returns value RELATION_NONE.
 *         if port1 == port2, returns value RELATION_1_EQUIV_2.
 *         if port1 is the subset of port2, returns value RELATION_1_SUBSET_2.
 *         if port1 is the superset of port2, returns value RELATION_1_SUPERSET_2.
 *         if port1 and port2 are interleaving, returns value RELATION_1_INTERLEAVING_2.
 */
int Conflict::compareTwoPortRanges(u_int16_t port1_start, u_int16_t port1_stop, u_int16_t port2_start, u_int16_t port2_stop)
{
    if ( (compareTwoPortValues(port1_stop, port2_start) == RELATION_1_SMALLER_2) ||
         (compareTwoPortValues(port2_stop, port1_start) == RELATION_1_SMALLER_2) )
    {
        return RELATION_NONE;
    }
    else if ( (compareTwoPortValues(port1_start, port2_start) == RELATION_1_EQUIV_2) &&
              (compareTwoPortValues(port1_stop, port2_stop) == RELATION_1_EQUIV_2) )
    {
        return RELATION_1_EQUIV_2;
    }
    else if ( ((compareTwoPortValues(port1_start, port2_start) == RELATION_1_EQUIV_2) || (compareTwoPortValues(port1_start, port2_start) == RELATION_1_BIGGER_2)) &&
              ((compareTwoPortValues(port1_stop, port2_stop) == RELATION_1_EQUIV_2) || (compareTwoPortValues(port1_stop, port2_stop) == RELATION_1_SMALLER_2)))
    {
        return RELATION_1_SUBSET_2;
    }
    else if ( ((compareTwoPortValues(port1_start, port2_start) == RELATION_1_EQUIV_2) || (compareTwoPortValues(port1_start, port2_start) == RELATION_1_SMALLER_2)) &&
              ((compareTwoPortValues(port1_stop, port2_stop) == RELATION_1_EQUIV_2) || (compareTwoPortValues(port1_stop, port2_stop) == RELATION_1_BIGGER_2)))
    {
        return RELATION_1_SUPERSET_2;
    }
    else
    {
        return RELATION_1_INTERLEAVING_2;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed ranges of ports, considering if they are negated and returns the result of the comparison.
 *
 * @param port1_start value representing start port of the first range.
 * @param port1_stop value representing end port of the first range.
 * @param port1_neg flag set if the first range is negated.
 * @param port2_start value representing start port of the second range.
 * @param port2_stop value representing end port of the second range.
 * @param port2_neg fla set if the second range is negated.
 * @return value representing relation between range port1 (port1_start - port1_stop) and port2 (port2_start - port2_stop).
 *         if port1 != port2, returns value RELATION_NONE.
 *         if port1 == port2, returns value RELATION_1_EQUIV_2.
 *         if port1 is the subset of port2, returns value RELATION_1_SUBSET_2.
 *         if port1 is the superset of  port2, returns value RELATION_1_SUPERSET_2.
 *         if sets port1 and port2 are interleaving, returns value RELATION_1_INTERLEAVING_2.
 */
int Conflict::compareTwoPortRanges(u_int16_t port1_start, u_int16_t port1_stop, bool port1_neg, u_int16_t port2_start, u_int16_t port2_stop, bool port2_neg)
{
    int relation = compareTwoPortRanges(port1_start, port1_stop, port2_start, port2_stop);
    
    switch ( relation )
    {
        case RELATION_NONE:
            
            if ( !port1_neg && !port2_neg )
            {
                return RELATION_NONE;
            }
            else if ( port1_neg && !port2_neg )
            {
                return RELATION_1_SUPERSET_2;
            }
            else if ( !port1_neg && port2_neg )
            {
                return RELATION_1_SUBSET_2;
            }
            else /* if ( port1_neg && port2_neg ) */
            {
                return RELATION_1_INTERLEAVING_2;
            }

        case RELATION_1_EQUIV_2:
            
            if ( !port1_neg && !port2_neg )
            {
                return RELATION_1_EQUIV_2;
            }
            else if ( port1_neg && port2_neg )
            {
                return RELATION_1_EQUIV_2;
            }
            else /* if ( (!port1_neg && port2_neg) || (port1_neg && !port2_neg) ) */
            {
                return RELATION_NONE;
            }

        case RELATION_1_SUBSET_2:
            
            if ( !port1_neg && !port2_neg )
            {
                return RELATION_1_SUBSET_2;
            }
            else if ( port1_neg && !port2_neg )
            {
                return RELATION_1_INTERLEAVING_2;
            }
            else if ( !port1_neg && port2_neg )
            {
                return RELATION_NONE;
            }
            else /* if ( port1_neg && port2_neg ) */
            {
                return RELATION_1_SUPERSET_2;
            }

        case RELATION_1_SUPERSET_2:

            if ( !port1_neg && !port2_neg )
            {
                return RELATION_1_SUPERSET_2;
            }
            else if ( port1_neg && !port2_neg )
            {
                return RELATION_NONE;
            }
            else if ( !port1_neg && port2_neg )
            {
                return RELATION_1_INTERLEAVING_2;
            }
            else /* if ( port1_neg && port2_neg ) */
            {
                return RELATION_1_SUBSET_2;
            }

        /* RELATION_1_INTERLEAVING_2 */
        default:
            return RELATION_1_INTERLEAVING_2;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method compares two passed protocols and returns the result of the comparison.
 *
 * @param protocol1 numerical value representing first protokol (constant PROTO_XXX).
 * @param protocol2 numerical value representing second protokol (constant PROTO_XXX).
 * @return value representing relation between protocols protocol1 and protocol2.
 *         if protocol1 != protocol2, returns value RELATION_NONE.
 *         if protocol1 == protocol2, returns value RELATION_1_EQUIV_2.
 *         if protocol1 is the subset of protocol2, returns value RELATION_1_SUBSET_2.
 *         if protocol1 is the superset of protocol2, returns value RELATION_1_SUPERSET_2.
 */
int Conflict::compareProtocol(int protocol1, int protocol2)
{
    if ( protocol1 == protocol2 )
    {
        return RELATION_1_EQUIV_2;
    }
    else if ( protocol1 == PROTO_ANY )
    {
        return RELATION_1_SUPERSET_2;
    }
    else if ( protocol2 == PROTO_ANY )
    {
        return RELATION_1_SUBSET_2;
    }
    else if ( protocol1 == PROTO_IPv4 )
    {
        return RELATION_1_SUPERSET_2;
    }
    else if ( protocol2 == PROTO_IPv4 )
    {
        return RELATION_1_SUBSET_2;
    }

    return RELATION_NONE;
}

//-----------------------------------------------------------------------------------

/**
 * Method which according to current global relation between two rules and partial relation
 * between ich dimension returns result combination of these relations.
 *
 * @param globalRelation current global relation between two rules.
 * @param partialRelation partial relation between some dimension of rules.
 * @return value representing combination of relations globalRelation a partialRelation.
 *         if protocol1 != protocol2, returns value RELATION_NONE.
 *         if protocol1 == protocol2, returns value RELATION_1_EQUIV_2.
 *         if protocol1 is the subset of protocol2, returns value RELATION_1_SUBSET_2.
 *         if protocol1 is the superset of protocol2, returns value RELATION_1_SUPERSET_2.
 */
int Conflict::combineRelations(int globalRelation, int partialRelation)
{
    if ( partialRelation == RELATION_1_EQUIV_2 )
    {
        return globalRelation;
    }
    else if ( partialRelation == RELATION_1_SUBSET_2 )
    {
        if ( (globalRelation == RELATION_1_EQUIV_2) || (globalRelation == RELATION_1_SUBSET_2) )
        {
            return RELATION_1_SUBSET_2;
        }
        else if ( (globalRelation == RELATION_1_SUPERSET_2) || (globalRelation == RELATION_1_INTERLEAVING_2) )
        {
            return RELATION_1_INTERLEAVING_2;
        }
    }
    else if ( partialRelation == RELATION_1_SUPERSET_2 )
    {
        if ( (globalRelation == RELATION_1_EQUIV_2) || (globalRelation == RELATION_1_SUPERSET_2) )
        {
            return RELATION_1_SUPERSET_2;
        }
        else if ( (globalRelation == RELATION_1_SUBSET_2) || (globalRelation == RELATION_1_INTERLEAVING_2) )
        {
            return RELATION_1_INTERLEAVING_2;
        }
    }
    else if ( partialRelation == RELATION_1_INTERLEAVING_2 )
    {
        if ( globalRelation != RELATION_NONE )
        {
            return RELATION_1_INTERLEAVING_2;
        }
    }

    return RELATION_NONE;
}

//-----------------------------------------------------------------------------------

/**
 * Method according to relation between two rules and their actions determines the type of the conflict between rules.
 *
 * @param rule_Y_and_X_relation value representing relation between the rules.
 * @param ruleYaction action of rule ruleY.
 * @param ruleXaction action of rule ruleX.
 * @return value representing resulting conflict between rules (constant CONFLICT_XXX).
 */
int Conflict::resolveConflictType(int rule_Y_and_X_relation, int ruleYaction, int ruleXaction)
{
    if ( (rule_Y_and_X_relation == RELATION_1_EQUIV_2) || (rule_Y_and_X_relation == RELATION_1_SUBSET_2) )
    {
        if ( ruleYaction == ruleXaction )
        {
            return CONFLICT_REDUNDANCY;
        }
        else
        {
            return CONFLICT_SHADOWING;
        }
    }
    else if ( rule_Y_and_X_relation == RELATION_1_SUPERSET_2 )
    {
        if ( ruleYaction == ruleXaction )
        {
            return CONFLICT_REDUNDANCY;
        }
        else
        {
            return CONFLICT_GENERALIZATION;
        }
    }
    else if ( rule_Y_and_X_relation == RELATION_1_INTERLEAVING_2 )
    {
        if ( ruleYaction == ruleXaction )
        {
            return CONFLICT_SUPERIMPOSING;
        }
        else
        {
            return CONFLICT_CORELATION;
        }
    }
    else
    {
        return CONFLICT_NONE;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method converts numerical value to string.
 *
 * @param type value representing type of the conflict (constant CONFLICT_XXX).
 * @return string representing the type of the conflict.
 */
string Conflict::conflictTypeToString(int type)
{
    switch (type)
    {
        case CONFLICT_NONE:
            return "no_conflict";

        case CONFLICT_CORELATION:
            return "correlation";

        case CONFLICT_GENERALIZATION:
            return "generalization";

        case CONFLICT_REDUNDANCY:
            return "redundancy";

        case CONFLICT_SHADOWING:
            return "shadowing";

        case CONFLICT_SUPERIMPOSING:
            return "superimposing";

        default:
            return "";
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method converts numerical representation of the relation (of rules, dimensions, ...) to string.
 *
 * @param type value representing type of the relation (constant RELATION_XXX).
 * @return string representing the relation.
 */
string Conflict::relationTypeToString(int type)
{
    switch (type)
    {
        case RELATION_NONE:
            return "no_relation";

        case RELATION_1_SUPERSET_2:
            return "Y_superset_of_X";

        case RELATION_1_SUBSET_2:
            return "Y_subset_of_X";

        case RELATION_1_EQUIV_2:
            return "Y_equivalent_X";

        case RELATION_1_INTERLEAVING_2:
            return "Y_interleaving_X";

        case RELATION_1_BIGGER_2:
            return "Y_bigger_than_X";

        case RELATION_1_SMALLER_2:
            return "Y_smaller_than_X";

        default:
            return "";
    }
}
