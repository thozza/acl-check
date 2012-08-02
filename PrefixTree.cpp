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

#include "PrefixTree.hpp"
#include "GlobalDefs.hpp"

using namespace std;

/**
 * Class constructor.
 */
PrefixTree::TreeNode::TreeNode() : m_parent(NULL), m_0_Lchild(NULL), m_1_Rchild(NULL), m_isValidPrefixNode(false) { }

//-----------------------------------------------------------------------------------

/**
 * Class constructor.
 *
 * @param parent pointer to node which is parent of this new node in trie.
 */
PrefixTree::TreeNode::TreeNode(PrefixTree::TreeNode* parent) : m_parent(parent), m_0_Lchild(NULL), m_1_Rchild(NULL), m_isValidPrefixNode(false) { }

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
PrefixTree::TreeNode::~TreeNode() { }


/*************************************************************/
/************************ PREFIX TREE ************************/

/**
 * Class constructor.
 *
 * @param aclSize number of rules in ACL for which is this prefix tree used.
 */
PrefixTree::PrefixTree(u_int32_t aclSize) : m_rootNode(new TreeNode()), m_numOfAclRules(aclSize)
{
    m_allTreeNodes.push_back(m_rootNode);
}

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
PrefixTree::~PrefixTree() { }

//-----------------------------------------------------------------------------------

/**
 * Method for allocating new tree node.
 * 
 * Method allocates new tree node with passed parent and returns the pointer to new tree node.
 *
 * @param parent pointer to parent node.
 * @return pointer to newly created node.
 */
PrefixTree::TreeNode* PrefixTree::allocateNewNode(PrefixTree::TreeNode* const parent)
{
    /* kontrola parametrov */
    if ( parent == NULL )
    {
        cerr << "ERROR-PrefixTree: Parameter \"parent\" for new TreeNode is NULL!";
        #ifdef DEBUG
        cerr << "(file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        exit(1);
    }

    TreeNode* newNode = new TreeNode(parent);
    m_allTreeNodes.push_back(newNode);

    return newNode;
}

//-----------------------------------------------------------------------------------

/**
 * Method recursively computes BitVector2 for subtree with passed root node.
 *
 * @param node pointer to tree node used as root for the subtree for which the BitVector2 is computed.
 * @param vector reference to the object WAHBitVector where computed BitVector2 will be stored.
 */
void PrefixTree::getBitVector2forSubTree(PrefixTree::TreeNode* const node, WAHBitVector& vector)
{
    /* parameters's check */
    if ( node == NULL )
        return;

    /* if the current node is valid, we do OR and return */
    if ( node->m_isValidPrefixNode )
    {
        vector |= *(node->m_bitVector2);

        return;
    }

    /* continue with left subtree */
    getBitVector2forSubTree(node->m_0_Lchild, vector);

    /* continue with right subtree */
    getBitVector2forSubTree(node->m_1_Rchild, vector);
}

//-----------------------------------------------------------------------------------

/**
 * Method adds new rule to the tree according to its prefix.
 *
 * @param prefix reference to bit vector containing prefix which will be added.
 * @param rulePositionNum position of the rule in ACL.
 * @return smart pointer with pointer to the object WAHBitVector containing conflict bit vector for new rule.
 */
std::auto_ptr< WAHBitVector > PrefixTree::addNewRulePrefix(const boost::dynamic_bitset< >& prefix, int rulePositionNum)
{
    /* conflict vector for newly added rule */
    auto_ptr< WAHBitVector > conflictVector(new WAHBitVector(m_numOfAclRules));

    TreeNode* curentNode = m_rootNode;
    unsigned prefixSize = prefix.size();

    /* traversing the tree according to the prefix */
    for ( unsigned i = 0; i < prefixSize; ++i )
    {
        /* if the current tree represents valid prefix -> set bitVector2 and do OR with conflictVector */
        if ( curentNode->m_isValidPrefixNode )
        {
            curentNode->m_bitVector2->set(rulePositionNum);
            *conflictVector |= *(curentNode->m_bitVector1);
        }

        /* shift to next node in tree */
        /* if there is value "1" at the current position of the prefix -> shift to right child */
        if ( prefix[i] )
        {
            /* if there is no right child */
            if ( curentNode->m_1_Rchild == NULL )
                curentNode->m_1_Rchild = allocateNewNode(curentNode);

            curentNode = curentNode->m_1_Rchild;
            continue;
        }
        /*if there is value "0" at the current position of the prefix -> shift to left child */
        else
        {
            /* if there is no left child */
            if ( curentNode->m_0_Lchild == NULL )
                curentNode->m_0_Lchild = allocateNewNode(curentNode);

            curentNode = curentNode->m_0_Lchild;
            continue;
        }
    }

    /* we traversed to the node which corresponds exactly with prefix of current rule */
    /* just to be sure, check of current node -> that should never happen!!! */
    if ( curentNode == NULL )
    {
        cerr << "ERROR-PrefixTree: Error while adding new rule #" << rulePositionNum;
        #ifdef DEBUG
        cerr << " (file:" << __FILE__ << ",line:" << __LINE__ << ")";
        #endif
        cerr << endl;

        exit(1);
    }

    /* if the current node represents valid prefix */
    if ( curentNode->m_isValidPrefixNode )
    {
        curentNode->m_bitVector1->set(rulePositionNum);
        curentNode->m_bitVector2->set(rulePositionNum);
    }
    else
    {
        /* create bit vectors */
        curentNode->m_bitVector1 = auto_ptr< WAHBitVector > (new WAHBitVector(m_numOfAclRules));
        curentNode->m_bitVector2 = auto_ptr< WAHBitVector > (new WAHBitVector(m_numOfAclRules));

        curentNode->m_bitVector1->set(rulePositionNum);
        curentNode->m_bitVector2->set(rulePositionNum);

        getBitVector2forSubTree(curentNode, *(curentNode->m_bitVector2));

        curentNode->m_isValidPrefixNode = true;
    }

    *conflictVector |= *(curentNode->m_bitVector2);
    
    return conflictVector;
}