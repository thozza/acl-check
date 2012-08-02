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

#include "AclRule.hpp"
#include "PrefixTree.hpp"

#ifndef PREFIX_FOREST_H__651351754168484351169411344616164137418631356816168454
#define PREFIX_FOREST_H__651351754168484351169411344616164137418631356816168454

/**
 * Class PrefixForest represents the forest of prefix tress.
 */
class PrefixForest
{
    private:
        const u_int32_t m_numOfAclRules;                /** Value representing the number of rules in ACL. */
        const int m_numOfRuleDimensions;                /** Value representing the number of dimensions of rules. */
        boost::ptr_vector< PrefixTree > m_triesVector;  /** Smart container (vector) containing objects of PrefixTree-s. */

    public:
        PrefixForest(u_int32_t aclSize, int numOfDimensions = (DIMENSION_MAX + 1));
        virtual ~PrefixForest();

        std::auto_ptr< WAHBitVector > addAclRule(const AclRule& rule);
};

#endif /* PREFIX_FOREST_H__651351754168484351169411344616164137418631356816168454 */