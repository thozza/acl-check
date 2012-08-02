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
#include <boost/dynamic_bitset.hpp>
#include <boost/ptr_container/ptr_vector.hpp>

#include "WAHBitVector.hpp"

#ifndef PREFIX_TREE_H_863418738481687421681315418613438413414341684416838
#define PREFIX_TREE_H_863418738481687421681315418613438413414341684416838

/**
 * Class PrefixTree represents the prefix tree for one dimension of ACL rule.
 */
class PrefixTree
{
    protected:
        /**
         * Class TreeNode represents the node of a prefix tree.
         */
        class TreeNode
        {
            public:
                TreeNode* m_parent;     /** Pointer to the parent node. */
                TreeNode* m_0_Lchild;   /** Pointer to left child. */
                TreeNode* m_1_Rchild;   /** Pointer to right child. */

                std::auto_ptr< WAHBitVector > m_bitVector1;     /** Smart pointer containing BitVector1. */
                std::auto_ptr< WAHBitVector > m_bitVector2;     /** Smart pointer containing BitVector2. */
            
                bool m_isValidPrefixNode;       /** Flag set if the node represents valid prefix. */

                TreeNode();
                TreeNode(TreeNode* parent);
                virtual ~TreeNode();
        };

    private:
        TreeNode* const m_rootNode;                     /** Constant pointer to the root of the prefix tree. */
        const u_int32_t m_numOfAclRules;                /** Number of the rules in ACL for which the tree is created. */
        boost::ptr_vector< TreeNode > m_allTreeNodes;   /** Vector of pointers to all nodes of tree (the memory will be freed in destruction). */

    protected:
        TreeNode* allocateNewNode(TreeNode* const parent);
        void getBitVector2forSubTree(TreeNode* const node, WAHBitVector& vector);
        
    public:
        PrefixTree(u_int32_t aclSize);
        virtual ~PrefixTree();

        std::auto_ptr< WAHBitVector > addNewRulePrefix(const boost::dynamic_bitset< >& prefix, int rulePositionNum);
};

#endif /* PREFIX_TREE_H_863418738481687421681315418613438413414341684416838 */