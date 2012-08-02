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

#include <vector>
#include <string>
#include <sys/types.h>
#include <boost/dynamic_bitset.hpp>

#include "Exception.hpp"

#ifndef WAHBIT_VECTOR_H_832789326782748484924874678234
#define WAHBIT_VECTOR_H_832789326782748484924874678234

/**
* Class WAHBitVector (Word-Aligned Hybrid Bit Vector) represents compressed bit vector.
*
* WAHBitVector is compressed bit vector(Word-Aligned Hybrid Bit Vecotr),
* which implememntation focuses on saving memory when it contains large number of bits.
* The vector provides methods necessary for basic use and logical operations (AND, OR).
* Compression method used is hybrid compression RLE for repeating
* sequences of length which is a multiple of word length (word - 31bit [32. bit je flag])and no compression
* for non-repeating sequences shorter than one word.
*/
class WAHBitVector
{
    private:
        std::vector<u_int32_t> m_vec;       /** Vector containing 32bit words. */
        const u_int32_t m_sizeInBits;       /** Length of vector in bits */
            
        u_int32_t m_activeWordValue;        /** Variable containing the value of active word */
        u_int32_t m_activeWordBitsCnt;      /** Variable containing the number of valid bits in active word */

    public:
        class OnesIterator;         /** forward declaration of class OnesIterator */
            
        WAHBitVector(const u_int32_t size, bool setBit = false);
        virtual ~WAHBitVector() { };

        void set(const u_int32_t index) throw(Exception);
        bool get(const u_int32_t index) throw(Exception);
        u_int32_t size();
        std::string toStringHex();
        OnesIterator getOnesIterator(const u_int32_t stopIndex, const u_int32_t startIndex = 0) throw(Exception);

        boost::dynamic_bitset<> getUncompressedVector();

        WAHBitVector operator | (const WAHBitVector& vector2) const;
        WAHBitVector operator & (const WAHBitVector& vector2) const;
        WAHBitVector& operator |= (const WAHBitVector& vector2);
        WAHBitVector& operator &= (const WAHBitVector& vector2);

        /**
         * Class OnesIterator represents the iterator of bit vector WAHBitVector which iterates through set bits.
         *
         * OnesIterator is the iterator for iterating the positions of set bits 
         * in the vector WAHBitVector. Iterator remembers the last position and always returns index of next
         * set bit, if there is another set bit in the vector.
         */
        class OnesIterator
        {
            private:
                const std::vector<u_int32_t>::const_iterator m_iterBegin;       /** Iterator pointing to first item of vector */
                const std::vector<u_int32_t>::const_iterator m_iterEnd;         /** Iterator pointing to the end of the vector (to item after the last one) */
                const u_int32_t m_activeWordValue;                              /** Variable containing the value of an active word */
                const u_int32_t m_activeWordBitsCnt;                            /** Variable containing the number of valid bits in an active word */
                const u_int32_t m_vectorSize;                                   /** Variable containing the size of the vector in bits */
                std::vector<u_int32_t>::const_iterator m_iterator;              /** Iterator of the vector iterating through 32bit words of WAH bit vector */
                const u_int32_t m_startIndex;       /** Variable containing the value of start index from which we search set bits */
                const u_int32_t m_stopIndex;        /** Variable containing the value of end index to which we search set bits */

                bool m_reachedEnd;                  /** Flag set if we reached last bit of bit vector */
                int32_t m_lastOneIndex;             /** Variable containing the index of last found set bit */
                int32_t m_actRunStartIndex;         /** Variable containing first index of current 32bit word */
                int32_t m_actRunEndIndex;           /** Variable containing last index of current 32bit word */
                    
            public:
                OnesIterator(std::vector<u_int32_t>::const_iterator begin, std::vector<u_int32_t>::const_iterator end, u_int32_t awValue, u_int32_t awBits, u_int32_t size, u_int32_t stopIndex, u_int32_t startIndex = 0);
                ~OnesIterator() { };
                int32_t next();
        };

    protected:

        /**
         * Class VectorRun decodes current 32bit word ('RUN').
         * 
         * Class provides iterating through 32bit words (RUNs) of WAH bit vector, which internally
         * represent it. 32bit RUN contains 31 bits of bit vector and one system flag.
         * System flag is the MSB (Most Significant Bit) nad represents if current RUN is RUN FILL or LITERAL.
         * FILL codes several 31bit sequences of Ones or Zeroes into single one.
         * LITERAL is literal representation of some mixed 31bit sequence of Ones and Zeroes.
         */
         class VectorRun
         {
             public:
                 const std::vector<u_int32_t>::const_iterator m_iterEnd;
                 std::vector<u_int32_t>::const_iterator m_iterator;             /** Iterator of 32bit words of WAH bit vector */
                 u_int32_t m_word;           /** One word (31bit) representation of "FILL" or "LITERAL" */
                 u_int32_t m_wordsCount;     /** Number of words coded in actual "RUN" */
                 bool m_isFill;              /** Is actual RUN a FILL? */

                 VectorRun(std::vector< u_int32_t>::const_iterator begin, std::vector< u_int32_t>::const_iterator end);
                 void decodeRun();
                 bool isExhausted();
                 static void appendLiteral(std::vector<u_int32_t>& vec, u_int32_t value);
                 static void appendFill(std::vector<u_int32_t>& vec, u_int32_t numOfRuns, u_int32_t fillBit);
          };
};

#endif /* WAHBIT_VECTOR_H_832789326782748484924874678234 */