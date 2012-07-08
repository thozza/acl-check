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

#include <boost/dynamic_bitset.hpp>

#include <string>
#include <sys/types.h>

#include "ProtocolsDef.hpp"
#include "PortsDef.hpp"
#include "Exception.hpp"

#ifndef ACL_RULE_HPP__2183676564362387987367512378930671238938
#define ACL_RULE_HPP__2183676564362387987367512378930671238938

/**
 * Structure for representing IPv4 address in form of A.B.C.D.
 */
typedef struct {
    u_int8_t D;         /** value from 0 to 255 */
    u_int8_t C;         /** value from 0 to 255 */
    u_int8_t B;         /** value from 0 to 255 */
    u_int8_t A;         /** value from 0 to 255 */
} IP_ADDRESS;

/**
 * Constants representing dimensions (fields) of an ACL rule.
 */
const int DIMENSION_PROTO = 0;          /** Communication protocol */
const int DIMENSION_SRC_IP = 1;         /** Source IP address */
const int DIMENSION_DST_IP = 2;         /** Destination IP address */
const int DIMENSION_SRC_PRT = 3;        /** Source port */
const int DIMENSION_DST_PRT = 4;        /** Destination port */

const int DIMENSION_MIN = DIMENSION_PROTO;      /** Minimum valid dimension value. */
const int DIMENSION_MAX = DIMENSION_DST_PRT;    /** Maximum valid dimension value. */

/**
 * Constants representing valid rule actions.
 */
const int ACTION_ALLOW = 0;     /** Permit matching packets. */
const int ACTION_DENY = 1;      /** Deny matching packets. */

/**
 * Class AclRule represents a ACL rule.
 *
 * Object of this class represents some particular rule of some ACL.
 * Class provides all necessary GET and SET methods.
 */
class AclRule
{
    private:
        IP_ADDRESS m_srcIP_start;               /** Start IPv4 address of source address range. */
        IP_ADDRESS m_srcIP_stop;                /** End IPv4 address of source address range. */
        boost::dynamic_bitset<> m_srcIP_prefix; /** Source address range in prefix form ("super-prefix"). */
        
        IP_ADDRESS m_dstIP_start;               /** Start IPv4 address of destination address range. */
        IP_ADDRESS m_dstIP_stop;                /** End IPv4 address of destination address range. */
        boost::dynamic_bitset<> m_dstIP_prefix; /** Destination address range in prefix form ("super-prefix"). */

        int m_protocol;                                 /** Value representing communication protocol. */
        boost::dynamic_bitset<> m_protocol_prefix;      /** Communication protocol value in prefix form. */
        
        u_int16_t m_srcPort_start;                      /** Start port number of source port range. */
        u_int16_t m_srcPort_stop;                       /** End port number of source port range. */
        boost::dynamic_bitset<> m_srcPort_prefix;       /** Source port range in prefix form ("super-prefix"). */
        bool m_srcPortNeg;                              /** Flag representing if port range is negated/inverted. */

        u_int16_t m_dstPort_start;                      /** Start port number of destination port range. */
        u_int16_t m_dstPort_stop;                       /** End port number of destination port range. */
        boost::dynamic_bitset<> m_dstPort_prefix;       /** Destination port range in prefix form ("super-prefix"). */
        bool m_dstPortNeg;                              /** Flag representing if port range is negated/inverted. */

        int m_action;                           /** Rule action. */

        const unsigned m_rulePositionNumber;    /** Rule position in some ACL (counting from value "0"). */
        std::string m_name;                     /** Rule name (used mainly by Juniper devices). */

    protected:
        void computeSrcIpPrefix();
        void computeDstIpPrefix();
        void computeSrcPortPrefix();
        void computeDstPortPrefix();
        void computeProtoPrefix();

        void computeSrcIpStartStop();
        void computeDstIpStartStop();
        void computeSrcPortStartStop();
        void computeDstPortStartStop();
        
    public:
        AclRule(unsigned position);
        AclRule(unsigned position, std::string name);
        virtual ~AclRule();

        static std::string protocolToString(int protocol);
        static std::string portToString(u_int16_t port);

        /******** GET methods ********/
        std::string getSrcIpRangeString() const;
        const IP_ADDRESS& getSrcIpStart() const;
        const IP_ADDRESS& getSrcIpStop() const;
        const boost::dynamic_bitset<>& getSrcIpPrefix() const;

        std::string getDstIpRangeString() const;
        const IP_ADDRESS& getDstIpStart() const;
        const IP_ADDRESS& getDstIpStop() const;
        const boost::dynamic_bitset<>& getDstIpPrefix() const;

        std::string getSrcPortRangeString() const;
        u_int16_t getSrcPortStart() const;
        u_int16_t getSrcPortStop() const;
        const boost::dynamic_bitset<>& getSrcPortPrefix() const;
        bool getSrcPortNeg() const;

        std::string getDstPortRangeString() const;
        u_int16_t getDstPortStart() const;
        u_int16_t getDstPortStop() const;
        const boost::dynamic_bitset<>& getDstPortPrefix() const;
        bool getDstPortNeg() const;

        std::string getProtocolString() const;
        int getProtocol() const;
        const boost::dynamic_bitset<>& getProtocolPrefix() const;

        std::string getActionString() const;
        int getAction() const;

        unsigned getPosition() const;
        std::string getName() const;

        std::string getFieldString(int dimension) const throw(Exception);
        const boost::dynamic_bitset<>& getFieldPrefix(int dimension) const throw(Exception);

        /******** SET methods ********/
        void setSrcIP(u_int8_t startA, u_int8_t startB, u_int8_t startC, u_int8_t startD, u_int8_t stopA, u_int8_t stopB, u_int8_t stopC, u_int8_t stopD, bool compute_prefix = true);
        void setSrcIP(const IP_ADDRESS& start, const IP_ADDRESS& stop, bool compute_prefix = true);
        void setSrcIP(const boost::dynamic_bitset< >& srcIPprefix, bool compute_start_stop = true);

        void setDstIP(u_int8_t startA, u_int8_t startB, u_int8_t startC, u_int8_t startD, u_int8_t stopA, u_int8_t stopB, u_int8_t stopC, u_int8_t stopD, bool compute_prefix = true);
        void setDstIP(const IP_ADDRESS& start, const IP_ADDRESS& stop, bool compute_prefix = true);
        void setDstIP(const boost::dynamic_bitset< >& dstIPprefix, bool compute_start_stop = true);

        void setSrcPort(u_int16_t start, u_int16_t stop, bool negated = false, bool compute_prefix = true);
        void setSrcPort(const boost::dynamic_bitset< >& srcPortPrefix, bool compute_start_stop = true);

        void setDstPort(u_int16_t start, u_int16_t stop, bool negated = false, bool compute_prefix = true);
        void setDstPort(const boost::dynamic_bitset< >& dstPortPrefix, bool compute_start_stop = true);

        int setProtocol(int protocol);
        int setAction(int action);

        /**
        * Operator << used for printing the rule information to the given output stream (std::ostream).
        *
        * Operator used for printing the rule information to the given output stream in following format:
        * 'ACTION proto="PROTOCOL" srcIP="SOURCE IP RANGE" srcPort="SOURCE PORT RANGE" dstIP="DESTINATION IP RANGE" dstPort="DESTINATION PORT RANGE"'.
        * 
        * Field "proto" can contain protocol number or string representing set protocol.
        * 
        * Field "srcIP" and "dstIP" can contain range of IP address in the form of "x.x.x.x-y.y.y.y",
        * just one IP address in the form of "x.x.x.x" if start and end range address are the same
        * or key-word "any" representing range of "0.0.0.0-255.255.255.255".
        * 
        * Field "srcPort" and "dstPort" can contain range of TCP/UDP ports in the form of "xxx-yyy", where xxx and yyy
        * are number values representing port, key-words representing particular well-known port number
        * or key-word "any" is used for representing port range of "0-65535". If start and end port number of the range
        * are the same, the range is printed as a single port number "xxx". If the port range is inverted/negated, it is
        * printed in the form of "not(xxx-yyy)" or eventually "not(xxx)".
        *
        * @param out reference to the output stream.
        * @param rule reference to the rule object.
        * @return reference to the output stream previously passed as a parameter.
        */
        friend std::ostream& operator<<(std::ostream& out, const AclRule& rule);
};

#endif /* ACL_RULE_HPP__2183676564362387987367512378930671238938 */