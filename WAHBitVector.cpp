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
#include <vector>
#include <sstream>
#include <iomanip>
#include <string>

#include "WAHBitVector.hpp"
#include "Exception.hpp"

using namespace std;

/**
 * Class constructor.
 *
 * New compressed vector with passed size is created. The size is fixed after construction and 
 * it is not possible to change it!
 *
 * @param size size of created vector in bits.
 * @param fillBit initial value for all bits of newly created vector.
 */
WAHBitVector::WAHBitVector(const u_int32_t size, bool fillBit) : m_sizeInBits(size), m_activeWordValue(0)
{
    m_activeWordBitsCnt = size % 31;        /* number of bits, less than 31 which are not compressed */
    u_int32_t numOfWords = size / 31;       /* number of words in FILL */

    if ( fillBit )
        m_activeWordValue = 0xFFFFFFFF;
    
    if (numOfWords > 0)
    {
        if ( fillBit )
            numOfWords |= 0xC0000000;   /* set MSB bit to signalize that it is FILL of ones*/
        else
            numOfWords |= 0x80000000;   /* set MSB bit to signalize that it is FILL of zeroes*/

        m_vec.assign(1, numOfWords);    /* add FILL to vector */
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method sets the bit at passed index to value "1".
 *
 * @throw Exception if it is not possible to set a bit due to error, an exception is thrown.
 * @param index position of the bit to be set to value 1. Position has to be 
 * less than size of the vector - 1.
 */
void WAHBitVector::set(const u_int32_t index) throw(Exception)
{
    if ( index >= m_sizeInBits )
        throw Exception("Index out of borders!");

    /* if we want to set a bit in active word */ 
    if ( index >= (m_sizeInBits - m_activeWordBitsCnt) )
    {
        u_int32_t maska = 0x80000000 >> (index % 31);   /* construct a mask with one at the position */
        m_activeWordValue |= maska;                     /* set bit to '1' */

        return;
    }
    /* set a bit in some RUN in the vector */
    else
    {
        std::vector<u_int32_t>::iterator iter = m_vec.begin();
        u_int32_t actRunStartIndex = 0;
        
        /* shift to the proper RUN */
        while ( iter < m_vec.end() )
        {
            /* if the current RUN is FILL */
            if ( *iter > 0x7FFFFFFF )
            {
                /* if searched index belongs to this FILL */
                if ( (index >= actRunStartIndex) && (index < (actRunStartIndex + (31 * (*iter & 0x3FFFFFFF)))) )
                {
                    /* if this is FILL of ones --> return, the bit is already set */
                    if ( *iter > 0xC0000000 )
                        return;

                    /* if FILL codes the sequence of 31 zeroes */
                    if (*iter == 0x80000001)
                    {
                        *iter = 0;
                    }
                    /* if wanted index belongs to the first RUN, if we decompose FILL to RUNs */
                    else if ( index < actRunStartIndex + 31 )
                    {
                        --*iter;                  /* we decrease number of compressed 31-bit words */
                        iter = m_vec.insert(iter, 0);
                    }
                    /* if wanted index belongs to the last RUN, if we decompose FILL to RUNs */
                    else if ( index >= (actRunStartIndex + (31 * ((*iter & 0x3FFFFFFF) - 1))) )
                    {
                        --(*iter);                /* we decrease number of compressed 31-bit words */
                        iter = m_vec.insert(iter + 1, 0);
                    }
                    /* if wanted index belongs to some RUN in the middle, if we decompose FILL to RUNs */
                    else
                    {
                        u_int32_t runsInTheFront = (index - actRunStartIndex) / 31;     /* find out how many RUNs are before the RUN where we want to set a bit */
                        *iter -= runsInTheFront + 1;                                    /* we decrease number of RUNs before + one in which we want to set a bit */
                        runsInTheFront |= 0x80000000;                                   /* make a FILL from number of preceding RUNs */

                        iter = m_vec.insert(iter, runsInTheFront);
                        ++iter;
                        iter = m_vec.insert(iter, 0);
                    }

                    /* set wanted bit */
                    u_int32_t maska = 0x40000000 >> (index % 31);       /* construct a mask with one at the position */
                    *iter |= maska;
                    
                    return;
                }
                /* wanted index doesn't belong to current FILL */
                else
                {
                    actRunStartIndex += 31 * (*iter & 0x3FFFFFFF);      /* add number of compressed bits */
                    ++iter;     /* move to the following RUN */
                    continue;
                }
            }
            /* if the actual RUN is LITERAL */
            else
            {
                /* if wanted index belongs to this LITERAL */
                if ( (index >= actRunStartIndex) && (index < (actRunStartIndex + 31 )) )
                {
                    u_int32_t maska = 0x40000000 >> (index % 31);       /* construct a mask with one at the position */
                    *iter |= maska;

                    /* actual LITERAL contains only Ones --> change it to FILL */
                    if ( *iter == 0x7FFFFFFF )
                    {
                        /* if previous RUN is FILL of Ones */
                        if ( (iter > m_vec.begin()) && (*(iter - 1) > 0xC0000000) )
                        {
                            /* if also following RUN is FILL of Ones */
                            if ( ((iter + 1) < m_vec.end()) && (*(iter + 1) > 0xC0000000) )
                            {
                                /* combine previous, current and following RUN */
                                *(iter - 1) += (*(iter + 1) & 0x3FFFFFFF) + 1;
                                m_vec.erase(iter, iter + 1);
                                return;
                            }
                            else
                            {
                                /* add one FILL to preceding and delete current */
                                ++*(iter - 1);
                                m_vec.erase(iter);
                                return;
                            }
                        }
                        /* if preceding RUN is not FILL of Ones, but following is */
                        else if ( ((iter + 1) < m_vec.end()) && (*(iter + 1) > 0xC0000000) )
                        {
                            /* add one FILL to following and delete current */
                            ++*(iter + 1);
                            m_vec.erase(iter);
                            return;
                        }
                        /* if preceding nor following FILL is not FILL of Ones */
                        else
                        {
                            *iter = 0xC0000001; /* change LITERAL to FILL of Ones */
                            return;
                        }
                    }
                    return;
                }
                /* wanted index doesn't belong to current LITERAL */
                else
                {
                    actRunStartIndex += 31;      /* add number of bits in current LITERAL */
                    ++iter;     /* move to following RUN */
                    continue;
                }
            }
        }

        throw Exception("Unexpected error occurred while setting bit!");
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting value of bit on passed index.
 *
 * @throw Exception if it is not possible to get a bit value due to error, an exception is thrown.
 * @param index position of the bit we want to get its value. Position has to be 
 * less than size of the vector - 1.
 * @return hodota bitu so zadanym indexom.
 */
bool WAHBitVector::get(const u_int32_t index) throw(Exception)
{
    if ( index >= m_sizeInBits )
        throw Exception("Index out of borders!");

    /* if we want to get bit value from ActiveWord */
    if ( index >= (m_sizeInBits - m_activeWordBitsCnt) )
    {
        u_int32_t maska = 0x80000000 >> (index % 31);   /* construct a mask with one at the position */

        return ( (m_activeWordValue & maska) == maska );
    }
    /* we want to get bit value from some vector RUN */
    else
    {
        std::vector<u_int32_t>::iterator iter = m_vec.begin();
        u_int32_t actRunStartIndex = 0;

        /* move to wanted RUN */
        while ( iter != m_vec.end() )
        {
            /* if the actual RUN is FILL */
            if ( *iter > 0x7FFFFFFF )
            {
                /* if wanted index belongs to current FILL */
                if ( (index >= actRunStartIndex) && (index < (actRunStartIndex + (31 * (*iter & 0x3FFFFFFF)))) )
                {
                    return (*iter >= 0xC0000000) ? true : false;
                }
                else
                {
                    actRunStartIndex += 31 * (*iter & 0x3FFFFFFF);      /* add number of compressed bits */
                    ++iter;     /* move to next RUN */
                    continue;
                }
            }
            /* if the actual RUN is LITERAL */
            else
            {
                /* if wanted index belongs to current LITERAL */
                if ( (index >= actRunStartIndex) && (index < (actRunStartIndex + 31 )) )
                {
                    u_int32_t maska = 0x40000000 >> (index % 31);   /* construct a mask with one at the position */
                    return ( (m_activeWordValue & maska) == maska );
                }
                else
                {
                    actRunStartIndex += 31;      /* add number of bits in LITERAL */
                    ++iter;     /* move to next RUN */
                    continue;
                }
            }
        }

        throw Exception("Unexpected error occurred while setting bit!");
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method to get size of bit vector.
 *
 * @return number of bits in bit vector.
 */
u_int32_t WAHBitVector::size()
{
    return m_sizeInBits;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns string representing compressed vector for debug purposes.
 *
 * @return string containing internal representation of compressed bit vector.
 */
std::string WAHBitVector::toStringHex()
{
    std::stringstream output;
    std::vector<u_int32_t>::iterator it;

    for ( it = m_vec.begin(); it < m_vec.end(); ++it )
    {
        output << "0x";
        output << std::setw(8) << std::setfill('0') << std::right << std::hex << std::uppercase << *it << " ";
    }

    output << std::endl << "ActiveWord= ";
    output << "0x" << std::setw(8) << std::setfill('0') << std::right << std::hex << std::uppercase << m_activeWordValue << std::endl;
    output << "ActiveWordBits= " << std::dec << m_activeWordBitsCnt << std::endl;
    
    return output.str();
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the object of iterator through indeces of ones in current bit vector.
 *
 * @param stopIndex value of end index to which we want not iterate the positions of ones (not included).
 * @param startIndex value of start index from which we want to iterate the positions of one (included).
 * @return iterator through the indices of ones in current bit vector.
 */
WAHBitVector::OnesIterator WAHBitVector::getOnesIterator(const u_int32_t stopIndex, const u_int32_t startIndex) throw(Exception)
{
    if (stopIndex < startIndex)
        throw Exception("Stop index smaller than Start index!");

    u_int32_t stop = (stopIndex < size()) ? stopIndex : (size() - 1);

    return WAHBitVector::OnesIterator(m_vec.begin(), m_vec.end(), m_activeWordValue, m_activeWordBitsCnt, size(), stop, startIndex);
}

//-----------------------------------------------------------------------------------

/**
 * Method returns bit vector in non-compressed format.
 *
 * Method returns non-compressed bit vector represented by object boost::dynamic_bitset< >.
 *
 * @return non-compressed bit vector.
 */
boost::dynamic_bitset<> WAHBitVector::getUncompressedVector()
{
    boost::dynamic_bitset<> vector(m_sizeInBits, 0);
    u_int32_t index = 0;
    std::vector<u_int32_t>::iterator iter;

    for (iter = m_vec.begin(); iter < m_vec.end(); ++iter)
    {
        /* if the current RUN is FILL */
        if ( *iter > 0x7FFFFFFF )
        {
            u_int32_t numOfBits = *iter & 0x3FFFFFFF;
            numOfBits *= 31;

            /* it is FILL of ones */
            if ( *iter >= 0xC0000000 )
            {
                for (u_int32_t j = 0; j < numOfBits; ++j )
                    vector[index++] = true;
            }
            else
            {
                for (u_int32_t j = 0; j < numOfBits; ++j )
                    vector[index++] = false;
            }
        }
        /* if the current RUN is LITERAL */
        else
        {
            for (int i = 0; i < 31; ++i)
            {
                u_int32_t maska = 0x40000000 >> i;
                vector[index++] = ((*iter & maska) == maska);
            }
        }
    }

    for (u_int32_t i = 0; i < m_activeWordBitsCnt; ++i)
    {
        u_int32_t maska = 0x80000000 >> i;
        vector[index++] = ((m_activeWordValue & maska) == maska);
    }

    return vector;
}

//-----------------------------------------------------------------------------------

/**
 * Operator of logical AND.
 *
 * @param vector2 reference to the second bit vector.
 * @return new bit vector which is the AND of two vectors.
 */
WAHBitVector WAHBitVector::operator&(const WAHBitVector& vector2) const
{
    WAHBitVector result = *this;
    result &= vector2;
    return result;
}

//-----------------------------------------------------------------------------------

/**
 * Operator of logical OR.
 *
 * @param vector2 reference to he second bit vector.
 * @return new bit vector which is the OR of two vectors.
 */
WAHBitVector WAHBitVector::operator|(const WAHBitVector& vector2) const
{
    WAHBitVector result = *this;
    result |= vector2;
    return result;
}

//-----------------------------------------------------------------------------------

/**
 * Operator of logical AND with assignment.
 *
 * @param vector2 reference to the second bit vector.
 * @return reference to the original bit vector which is AND of original and the second vector.
 */
WAHBitVector& WAHBitVector::operator&=(const WAHBitVector& vector2)
{
    /* if the vectors are not empty, do AND also under words in the vector */
    if ( (!m_vec.empty()) && (!vector2.m_vec.empty()) )
    {
        std::vector<u_int32_t> newVector;

        WAHBitVector::VectorRun run1 = WAHBitVector::VectorRun(m_vec.begin(), m_vec.end());
        WAHBitVector::VectorRun run2 = WAHBitVector::VectorRun(vector2.m_vec.begin(), vector2.m_vec.end());

        while ( !run1.isExhausted() && !run2.isExhausted() )
        {
            if (run1.m_wordsCount == 0)
            {
                run1.decodeRun();
                ++run1.m_iterator;
            }

            if (run2.m_wordsCount == 0)
            {
                run2.decodeRun();
                ++run2.m_iterator;
            }

            if ( run1.m_isFill  && run2.m_isFill )
            {
                u_int32_t wordsCount = (run1.m_wordsCount < run2.m_wordsCount) ? run1.m_wordsCount : run2.m_wordsCount;
                WAHBitVector::VectorRun::appendFill(newVector, wordsCount, run1.m_word & run2.m_word);
                run1.m_wordsCount -= wordsCount;
                run2.m_wordsCount -= wordsCount;
            }
            else
            {
                WAHBitVector::VectorRun::appendLiteral(newVector, run1.m_word & run2.m_word);
                --run1.m_wordsCount;
                --run2.m_wordsCount;
            }
        }

        m_vec = newVector;
    }
    
    m_activeWordValue &= vector2.m_activeWordValue;

    return *this;
}

//-----------------------------------------------------------------------------------

/**
 * Operator of logical OR with assignment.
 *
 * @param vector2 reference to the second bit vector.
 * @return reference to the original bit vector which is logical OR of original and the second vector.
 */
WAHBitVector& WAHBitVector::operator|=(const WAHBitVector& vector2)
{
    /* ak nie su vectory prazdne, rabime AND aj nad slovami vo vectore */
    if ( (!m_vec.empty()) && (!vector2.m_vec.empty()) )
    {
        std::vector<u_int32_t> newVector;

        WAHBitVector::VectorRun run1 = WAHBitVector::VectorRun(m_vec.begin(), m_vec.end());
        WAHBitVector::VectorRun run2 = WAHBitVector::VectorRun(vector2.m_vec.begin(), vector2.m_vec.end());

        while ( !run1.isExhausted() && !run2.isExhausted() )
        {
            if (run1.m_wordsCount == 0)
            {
                run1.decodeRun();
                ++run1.m_iterator;
            }

            if (run2.m_wordsCount == 0)
            {
                run2.decodeRun();
                ++run2.m_iterator;
            }

            if ( run1.m_isFill  && run2.m_isFill )
            {
                u_int32_t wordsCount = (run1.m_wordsCount < run2.m_wordsCount) ? run1.m_wordsCount : run2.m_wordsCount;
                WAHBitVector::VectorRun::appendFill(newVector, wordsCount, run1.m_word | run2.m_word);
                run1.m_wordsCount -= wordsCount;
                run2.m_wordsCount -= wordsCount;
            }
            else
            {
                WAHBitVector::VectorRun::appendLiteral(newVector, run1.m_word | run2.m_word);
                --run1.m_wordsCount;
                --run2.m_wordsCount;
            }
        }

        m_vec = newVector;
    }
    
    m_activeWordValue |= vector2.m_activeWordValue;

    return *this;
}

/********************************************************/
/************ IMPLEMENTATION OF OnesIterator ************/
/********************************************************/

/**
 * Class constructor.
 *
 * The only meaningful way how to acquire the obect of class OnesIterator is by the method of class
 * WAHBitVector, as necessary parameters for its construction are private variables of class
 * WAHBitVector.
 *
 * @param begin iterator pointing to the start of the vector of 32bit words.
 * @param end iterator pointing to the end of the vector of 32bit words.
 * @param awValue value of active word.
 * @param awBits number of valid bits in active word.
 * @param size size of bit vector which is being iterated by this object, in bits.
 * @param stopIndex end index to which we want to search ones in the vector (not included).
 * @param startIndex start index from which we want to search ines in the vector (included).
 */
WAHBitVector::OnesIterator::OnesIterator(std::vector< u_int32_t >::const_iterator begin, std::vector< u_int32_t >::const_iterator end, u_int32_t awValue, u_int32_t awBits, u_int32_t size, u_int32_t stopIndex, u_int32_t startIndex) : m_iterBegin(begin),
              m_iterEnd(end),
              m_activeWordValue(awValue),
              m_activeWordBitsCnt(awBits),
              m_vectorSize(size),
              m_iterator(begin),
              m_startIndex(startIndex),
              m_stopIndex(stopIndex),
              m_reachedEnd(false),
              m_lastOneIndex(((int32_t)startIndex) - 1)
{
    /* vector of words is empty ot startindex is in active word */
    if ( (m_iterator == m_iterEnd) || (m_startIndex >= (m_vectorSize - m_activeWordBitsCnt)))
    {
        m_iterator = m_iterEnd;
        m_actRunStartIndex =  m_vectorSize - m_activeWordBitsCnt;
        m_actRunEndIndex = m_vectorSize - 1;
    }
    /* start index is in some word of the vector */
    else
    {
        m_actRunStartIndex = 0;
        m_actRunEndIndex = (*m_iterator > 0x7FFFFFFF) ? ((31 * (*m_iterator & 0x3FFFFFFF)) - 1) : 30;
        
        /* till shift to required RUN */
        while ( !(((int32_t)m_startIndex >= m_actRunStartIndex) && ((int32_t)m_startIndex <= m_actRunEndIndex)) )
        {
            m_actRunStartIndex = m_actRunEndIndex + 1;
            m_actRunEndIndex = (*m_iterator > 0x7FFFFFFF) ? ((31 * (*m_iterator & 0x3FFFFFFF)) + m_actRunEndIndex) : (m_actRunEndIndex + 31);
            ++m_iterator;
        }
    } 
}

//-----------------------------------------------------------------------------------

/**
 * Method returns the position of next one in the vector.
 *
 * If the method is called the first time, it returns the position of first found one in the vector.
 * After every other cal of the method, it returns the position of next one. If
 * there is no one in the vector, or the end of the vector is reached,
 * or the end index is reached, the method returns value -1.
 *
 * @return index of the next one. If there is no next one found, returns -1.
 *
 */
int32_t WAHBitVector::OnesIterator::next()
{
    /* if there is not end of the vector, search one */
    if (!m_reachedEnd)
    {
        /* the closest next position where one is searched */
        int32_t indexToCheck = m_lastOneIndex + 1;

        /* is this AFTER the end? */
        if (indexToCheck >= (int32_t)m_stopIndex)
        {
            m_reachedEnd = true;
            return -1;
        }
        
        /* search in vector of words */
        while ( m_iterator < m_iterEnd )
        {
            /* is the currently checked index within the current word? (RUN) If not ... */
            if ( indexToCheck > m_actRunEndIndex )
            {
                ++m_iterator;
                if ( m_iterator >= m_iterEnd )
                {
                    /* check also active word */
                    break;
                }
                
                m_actRunStartIndex = m_actRunEndIndex + 1;
                m_actRunEndIndex = (*m_iterator > 0x7FFFFFFF) ? ((31 * (*m_iterator & 0x3FFFFFFF)) + m_actRunEndIndex) : (m_actRunEndIndex + 31);
            }
            
            /* if the current RUN is FILL */
            if ( *m_iterator > 0x7FFFFFFF )
            {
                /* if this is the FILL of ones */
                if ( *m_iterator >= 0xC0000000 )
                {
                    m_lastOneIndex = indexToCheck;
                    return m_lastOneIndex;
                }
                /* if this is the FILL of zeroes */
                else
                {
                    /* within zeroes there is no one to be found, go to next word */
                    if ( (indexToCheck = m_actRunEndIndex + 1) >= (int32_t)m_stopIndex )
                    {
                        /* if the end index is reached, return */
                        m_reachedEnd = true;
                        return -1;
                    }
                    continue;
                }
            }
            /* it is literal */
            else
            {
                while ( indexToCheck <= m_actRunEndIndex )
                {
                    u_int32_t maska = 0x40000000 >> (indexToCheck % 31);

                    /* if the one is found */
                    if ( (*m_iterator & maska) == maska )
                    {
                        m_lastOneIndex = indexToCheck;
                        return m_lastOneIndex;
                    }

                    /* the one is not found, try next index */
                    if ( ++indexToCheck >= (int32_t)m_stopIndex )
                    {
                        /* if end index is reached, return */
                        m_reachedEnd = true;
                        return -1;
                    }
                }
                continue;
            }
        }

        /* vector is checked, search in active word */
        while ( indexToCheck < (int32_t)m_vectorSize )
        {
            u_int32_t maska = 0x80000000 >> (indexToCheck % 31);

            /* one was found */
            if ( (m_activeWordValue & maska) == maska )
            {
                m_lastOneIndex = indexToCheck;
                return m_lastOneIndex;
            }

            /* one is not found, try next index */
            if ( ++indexToCheck >= (int32_t)m_stopIndex )
                break;
        }

        /* if this is reached, no one has been found and this is the end */
        m_reachedEnd = true;
    }
    
    return -1;
}

/*****************************************************/
/************ IMPLEMENTATION OF VectorRun ************/
/*****************************************************/

/**
 * Class constructor.
 *
 * Class constructor with parameter which initializes the internal variable with the iterator of
 * vector of 32bit words of WAH bit vector. When constructing new object of the class, first RUN (pointed by passed iterator)
 * is automatically decoded. Passed iterator has to point to the first item of the vector.
 *
 * @param begin iterator pointing to the first item of the vector of 32bit words of WAH bit vector.
 * @param end iterator pointing to the end of the vector of 32bit words (to the item after the last valid item).
 */
WAHBitVector::VectorRun::VectorRun(std::vector< u_int32_t >::const_iterator begin, std::vector< u_int32_t >::const_iterator end) : m_iterEnd(end), m_iterator(begin), m_wordsCount(0)
{
}

//-----------------------------------------------------------------------------------

/**
 * Method for decoding actual RUN to which the iterator points.
 *
 * Method decodes RUN to which iterator of the object points. If in the 32bit word
 * to which the iterator points is the MSB set to value '1', RUN is decoded as a FILL. 
 * If the MSB is set to value '0', RUN is decoded as a LITERAL. During the decoding
 * process are proper private variables of the object set to actual values.
 * These private variables are accessible by class methods.
 */
void WAHBitVector::VectorRun::decodeRun()
{
    /* if the actual RUN is a FILL (MSB is '1') */
    if ( *m_iterator > 0x7FFFFFFF )
    {
        m_word = (*m_iterator >= 0xC0000000) ? 0x7FFFFFFF : 0x00000000;
        m_wordsCount = *m_iterator & 0x3FFFFFFF;
        m_isFill = true;
    }
    /* if the actual RUN is LITERAL */
    else
    {
        m_word = *m_iterator;
        m_wordsCount = 1;
        m_isFill = false;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method retuns value representing if is the vector exhausted.
 *
 * Method checks if the number of decoded words is zero and if
 * the iterator is at the end of vector.
 *
 * @return TRUE - if number of decoded words is zero (m_wordsCount == 0)
 *                and iterator reached the end of vector (m_iterator == m_iterEnd).
 *         FALSE - if there are some decoded words or the iterator is not at the end.
 */
bool WAHBitVector::VectorRun::isExhausted()
{
    return ( (m_iterator == m_iterEnd) && (m_wordsCount == 0) );
}

//-----------------------------------------------------------------------------------

/**
 * Method for appending LITERAL 32bit word value to the end of the vector.
 *
 * @param vec reference to the vector to which we want to append the word.
 * @param value 32bit word we want to append.
 */
void WAHBitVector::VectorRun::appendLiteral(std::vector< u_int32_t >& vec, u_int32_t value)
{
    if ( vec.empty() )
    {
        if ( value == 0 )
        {
            vec.push_back(0x80000001);
        }
        else if ( value == 0x7FFFFFFF )
        {
            vec.push_back(0xC0000001);
        }
        else
        {
            vec.push_back(value);
        }
    }
    /* we want to add just zeroes */
    else if ( value == 0 )
    {
        if ( vec.back() == 0 )
            vec.back() = 0x80000002;
        else if ( (vec.back() > 0x80000000) && (vec.back() < 0xC0000000) )
            ++vec.back();
        else
            vec.push_back(0x80000001);
    }
    /* we want to add just ones */
    else if ( value == 0x7FFFFFFF )
    {
        if ( vec.back() == 0x7FFFFFFF )
            vec.back() = 0xC0000002;
        else if ( vec.back() > 0xC0000000 )
            ++vec.back();
        else
            vec.push_back(0xC0000001);
    }
    /* we want to add some ones and zeroes mix */
    else
    {
        vec.push_back(value);
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for appending FILL 32bit word(s) value(s) to the end of the vector.
 *
 * @param vec reference to the vector to which we want to append the word.
 * @param numOfRuns number of words we want to add.
 * @param fillBit 31bit representation of the word value we want to add.
 */
void WAHBitVector::VectorRun::appendFill(std::vector< u_int32_t >& vec, u_int32_t numOfRuns, u_int32_t fillBit)
{
    if ( (numOfRuns > 1) && !vec.empty() )
    {
        if ( fillBit == 0 )
        {
            if ( (vec.back() >= 0x80000000) && (vec.back() < 0xC0000000) )
            {
                vec.back() += numOfRuns;
            }
            else
                vec.push_back(0x80000000 + numOfRuns);
        }
        else if ( vec.back() >= 0xC0000000 )
            vec.back() += numOfRuns;
        else
            vec.push_back(0xC0000000 + numOfRuns);
    }
    else if ( vec.empty() )
    {
        if ( fillBit == 0 )
            vec.push_back(0x80000000 + numOfRuns);
        else
            vec.push_back(0xC0000000 + numOfRuns);
    }
    else
    {
        appendLiteral(vec, fillBit);
    }
}