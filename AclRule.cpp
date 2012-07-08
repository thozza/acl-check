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
#include <sstream>
#include <cstdio>

#include "AclRule.hpp"

using namespace std;

/**
 * Class constructor.
 *
 * @param position position of the rule in ACL.
 */
AclRule::AclRule(unsigned position) : m_protocol(PROTO_ANY), m_srcPort_start(0), m_srcPort_stop(0xFFFF), m_srcPortNeg(false), m_dstPort_start(0), m_dstPort_stop(0xFFFF), m_dstPortNeg(false), m_action(ACTION_DENY), m_rulePositionNumber(position)
{
    m_srcIP_start.A = m_srcIP_start.B = m_srcIP_start.C = m_srcIP_start.D = 0;
    m_srcIP_stop.A = m_srcIP_stop.B = m_srcIP_stop.C = m_srcIP_stop.D = 255;
    m_dstIP_start.A = m_dstIP_start.B = m_dstIP_start.C = m_dstIP_start.D = 0;
    m_dstIP_stop.A = m_dstIP_stop.B = m_dstIP_stop.C = m_dstIP_stop.D = 255;

    stringstream ss;
    ss << position;
    m_name = string(ss.str());
}

//-----------------------------------------------------------------------------------

/**
 * Class constructor.
 *
 * @param position position of the rule in ACL.
 * @param name name of the rule (eg. used in Juniper ACLs).
 */
AclRule::AclRule(unsigned position, std::string name) : m_protocol(PROTO_ANY), m_srcPort_start(0), m_srcPort_stop(0xFFFF), m_srcPortNeg(false), m_dstPort_start(0), m_dstPort_stop(0xFFFF), m_dstPortNeg(false), m_action(ACTION_DENY), m_rulePositionNumber(position), m_name(name)
{
    m_srcIP_start.A = m_srcIP_start.B = m_srcIP_start.C = m_srcIP_start.D = 0;
    m_srcIP_stop.A = m_srcIP_stop.B = m_srcIP_stop.C = m_srcIP_stop.D = 255;
    m_dstIP_start.A = m_dstIP_start.B = m_dstIP_start.C = m_dstIP_start.D = 0;
    m_dstIP_stop.A = m_dstIP_stop.B = m_dstIP_stop.C = m_dstIP_stop.D = 255;
}

//-----------------------------------------------------------------------------------

/**
 * Class destructor.
 */
AclRule::~AclRule(){ }

//-----------------------------------------------------------------------------------

/**
 * Method computes prefix representation of source IPv4 range.
 *
 * Method computes approximate prefix representation (only single "superprefix")
 * of source IPv4 range based on already set values.
 */
void AclRule::computeSrcIpPrefix()
{
    /* using IP_ADDRESS structure as a 32bit unsigned int, for easier logical operations */
    u_int32_t srcIPxor = *((u_int32_t*)&m_srcIP_start) ^ *((u_int32_t*)&m_srcIP_stop);
    u_int32_t srcIPtmp = *((u_int32_t*)&m_srcIP_start);
    
    m_srcIP_prefix.clear();
    
    /* looking for first different bite (its value is "1") */
    for ( int i = 0; i < 32; ++i )
    {
        /* if we found the different bite -> we're finished */
        if ( (srcIPxor & 0x80000000) == 0x80000000 )
            break;

        /* add current bite value to the prefix representation */
        m_srcIP_prefix.push_back( (srcIPtmp & 0x80000000) == 0x80000000 );
        
        srcIPxor <<= 1;
        srcIPtmp <<= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes prefix representation of destination IPv4 range.
 *
 * Method computes approximate prefix representation (only single "superprefix")
 * of destination IPv4 range based on already set values.
 */
void AclRule::computeDstIpPrefix()
{
    /* using IP_ADDRESS structure as a 32bit unsigned int, for easier logical operations */
    u_int32_t dstIPxor = *((u_int32_t*)&m_dstIP_start) ^ *((u_int32_t*)&m_dstIP_stop);
    u_int32_t dstIPtmp = *((u_int32_t*)&m_dstIP_start);

    m_dstIP_prefix.clear();

    /* looking for first different bite (its value is "1") */
    for ( int i = 0; i < 32; ++i )
    {
        /* if we found the different bite -> we're finished */
        if ( (dstIPxor & 0x80000000) == 0x80000000 )
            break;

        /* add current bite value to the prefix representation */
        m_dstIP_prefix.push_back( (dstIPtmp & 0x80000000) == 0x80000000 );

        dstIPxor <<= 1;
        dstIPtmp <<= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes prefix representation of source port (TCP/UDP) range.
 *
 * Method computes approximate prefix representation (only single "superprefix")
 * of source port range based on already set values.
 */
void AclRule::computeSrcPortPrefix()
{
    m_srcPort_prefix.clear();

    /* if port range is NOT inverted/negated, we're computing prefix form.
     * Otherwise we leave prefix representation set as "any" == zero length.
     */
    if ( !m_srcPortNeg )
    {
        u_int16_t srcPortXor = m_srcPort_start ^ m_srcPort_stop;
        u_int16_t srcPortTmp = m_srcPort_start;

        /* looking for first different bite (its value is "1") */
        for ( int i = 0; i < 16; ++i )
        {
            /* if we found the different bite -> we're finished */
            if ( (srcPortXor & 0x8000) == 0x8000 )
                break;

            /* add current bite value to the prefix representation */
            m_srcPort_prefix.push_back( (srcPortTmp & 0x8000) == 0x8000 );

            srcPortXor <<= 1;
            srcPortTmp <<= 1;
        }
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes prefix representation of destination port (TCP/UDP) range.
 *
 * Method computes approximate prefix representation (only single "superprefix")
 * of destination port range based on already set values.
 */
void AclRule::computeDstPortPrefix()
{
    m_dstPort_prefix.clear();

    /* if port range is NOT inverted/negated, we're computing prefix form.
     * Otherwise we leave prefix representation set as "any" == zero length.
     */
    if ( !m_dstPortNeg )
    {
        u_int16_t dstPortXor = m_dstPort_start ^ m_dstPort_stop;
        u_int16_t dstPortTmp = m_dstPort_start;

        /* looking for first different bite (its value is "1") */
        for ( int i = 0; i < 16; ++i )
        {
            /* if we found the different bite -> we're finished */
            if ( (dstPortXor & 0x8000) == 0x8000 )
                break;

            /* add current bite value to the prefix representation */
            m_dstPort_prefix.push_back( (dstPortTmp & 0x8000) == 0x8000 );

            dstPortXor <<= 1;
            dstPortTmp <<= 1;
        }
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method sets prefix representation of IP protocol based on protocol number.
 *
 * Method sets prefix representation of used IP protocol based on protocol number
 * (represented by constant PROTO_xxx) to the value contained in corresponding constant
 * (named PROTO_xxx_PREFIX). In case we want to add new protocol, this constant has to be
 * manually calculated with the respect to all of the already calculated and added prefix
 * representations.
 */
void AclRule::computeProtoPrefix()
{
    m_protocol_prefix.clear();

    switch (m_protocol)
    {
        case PROTO_ANY:
            break;
            
        case PROTO_IPv4:
            m_protocol_prefix = PROTO_IPv4_PREFIX;
            break;

        case PROTO_HOPOPT:
            m_protocol_prefix = PROTO_HOPOPT_PREFIX;
            break;

        case PROTO_ICMPv4:
            m_protocol_prefix = PROTO_ICMPv4_PREFIX;
            break;

        case PROTO_IGMP:
            m_protocol_prefix = PROTO_IGMP_PREFIX;
            break;

        case PROTO_GGP:
            m_protocol_prefix = PROTO_GGP_PREFIX;
            break;

        case PROTO_IP_IN_IP:
            m_protocol_prefix = PROTO_IP_IN_IP_PREFIX;
            break;

        case PROTO_ST:
            m_protocol_prefix = PROTO_ST_PREFIX;
            break;

        case PROTO_TCP:
            m_protocol_prefix = PROTO_TCP_PREFIX;
            break;

        case PROTO_CBT:
            m_protocol_prefix = PROTO_CBT_PREFIX;
            break;

        case PROTO_EGP:
            m_protocol_prefix = PROTO_EGP_PREFIX;
            break;

        case PROTO_IGP:
            m_protocol_prefix = PROTO_IGP_PREFIX;
            break;

        case PROTO_BBN_RCC_MON:
            m_protocol_prefix = PROTO_BBN_RCC_MON_PREFIX;
            break;

        case PROTO_NVP_II:
            m_protocol_prefix = PROTO_NVP_II_PREFIX;
            break;

        case PROTO_PUP:
            m_protocol_prefix = PROTO_PUP_PREFIX;
            break;

        case PROTO_ARGUS:
            m_protocol_prefix = PROTO_ARGUS_PREFIX;
            break;

        case PROTO_EMCON:
            m_protocol_prefix = PROTO_EMCON_PREFIX;
            break;

        case PROTO_XNET:
            m_protocol_prefix = PROTO_XNET_PREFIX;
            break;

        case PROTO_CHAOS:
            m_protocol_prefix = PROTO_CHAOS_PREFIX;
            break;

        case PROTO_UDP:
            m_protocol_prefix = PROTO_UDP_PREFIX;
            break;

        case PROTO_MUX:
            m_protocol_prefix = PROTO_MUX_PREFIX;
            break;

        case PROTO_DCN_MEAS:
            m_protocol_prefix = PROTO_DCN_MEAS_PREFIX;
            break;

        case PROTO_HMP:
            m_protocol_prefix = PROTO_HMP_PREFIX;
            break;

        case PROTO_PRM:
            m_protocol_prefix = PROTO_PRM_PREFIX;
            break;

        case PROTO_XNS_IDP:
            m_protocol_prefix = PROTO_XNS_IDP_PREFIX;
            break;

        case PROTO_TRUNK_1:
            m_protocol_prefix = PROTO_TRUNK_1_PREFIX;
            break;

        case PROTO_TRUNK_2:
            m_protocol_prefix = PROTO_TRUNK_2_PREFIX;
            break;

        case PROTO_LEAF_1:
            m_protocol_prefix = PROTO_LEAF_1_PREFIX;
            break;

        case PROTO_LEAF_2:
            m_protocol_prefix = PROTO_LEAF_2_PREFIX;
            break;

        case PROTO_RDP:
            m_protocol_prefix = PROTO_RDP_PREFIX;
            break;

        case PROTO_IRTP:
            m_protocol_prefix = PROTO_IRTP_PREFIX;
            break;

        case PROTO_ISO_TP4:
            m_protocol_prefix = PROTO_ISO_TP4_PREFIX;
            break;

        case PROTO_NETBLK:
            m_protocol_prefix = PROTO_NETBLK_PREFIX;
            break;

        case PROTO_MFE_NSP:
            m_protocol_prefix = PROTO_MFE_NSP_PREFIX;
            break;

        case PROTO_METRIT_INP:
            m_protocol_prefix = PROTO_METRIT_INP_PREFIX;
            break;

        case PROTO_DCCP:
            m_protocol_prefix = PROTO_DCCP_PREFIX;
            break;

        case PROTO_3PC:
            m_protocol_prefix = PROTO_3PC_PREFIX;
            break;

        case PROTO_IDPR:
            m_protocol_prefix = PROTO_IDPR_PREFIX;
            break;

        case PROTO_XTP:
            m_protocol_prefix = PROTO_XTP_PREFIX;
            break;

        case PROTO_DDP:
            m_protocol_prefix = PROTO_DDP_PREFIX;
            break;

        case PROTO_IDPR_CMTP:
            m_protocol_prefix = PROTO_IDPR_CMTP_PREFIX;
            break;

        case PROTO_TP_PP:
            m_protocol_prefix = PROTO_TP_PP_PREFIX;
            break;

        case PROTO_IL:
            m_protocol_prefix = PROTO_IL_PREFIX;
            break;

        case PROTO_IPv4_IPv6:
            m_protocol_prefix = PROTO_IPv4_IPv6_PREFIX;
            break;

        case PROTO_SDRP:
            m_protocol_prefix = PROTO_SDRP_PREFIX;
            break;

        case PROTO_IPv4_IPv6_ROUTE:
            m_protocol_prefix = PROTO_IPv4_IPv6_ROUTE_PREFIX;
            break;

        case PROTO_IPv4_IPv6_FRAG:
            m_protocol_prefix = PROTO_IPv4_IPv6_FRAG_PREFIX;
            break;

        case PROTO_IDRP:
            m_protocol_prefix = PROTO_IDRP_PREFIX;
            break;

        case PROTO_RSVP:
            m_protocol_prefix = PROTO_RSVP_PREFIX;
            break;

        case PROTO_GRE:
            m_protocol_prefix = PROTO_GRE_PREFIX;
            break;

        case PROTO_DSR:
            m_protocol_prefix = PROTO_DSR_PREFIX;
            break;

        case PROTO_BNA:
            m_protocol_prefix = PROTO_BNA_PREFIX;
            break;

        case PROTO_ESP:
            m_protocol_prefix = PROTO_ESP_PREFIX;
            break;

        case PROTO_AH:
            m_protocol_prefix = PROTO_AH_PREFIX;
            break;

        case PROTO_I_NLSP:
            m_protocol_prefix = PROTO_I_NLSP_PREFIX;
            break;

        case PROTO_SWIPE:
            m_protocol_prefix = PROTO_SWIPE_PREFIX;
            break;

        case PROTO_NARP:
            m_protocol_prefix = PROTO_NARP_PREFIX;
            break;

        case PROTO_MOBILE:
            m_protocol_prefix = PROTO_MOBILE_PREFIX;
            break;

        case PROTO_TLSP:
            m_protocol_prefix = PROTO_TLSP_PREFIX;
            break;

        case PROTO_SKIP:
            m_protocol_prefix = PROTO_SKIP_PREFIX;
            break;

        case PROTO_IPv6_ICMP:
            m_protocol_prefix = PROTO_IPv6_ICMP_PREFIX;
            break;

        case PROTO_IPv6_NONXT:
            m_protocol_prefix = PROTO_IPv6_NONXT_PREFIX;
            break;

        case PROTO_IPv6_OPTS:
            m_protocol_prefix = PROTO_IPv6_OPTS_PREFIX;
            break;

        case PROTO_AHIP:
            m_protocol_prefix = PROTO_AHIP_PREFIX;
            break;

        case PROTO_CFTP:
            m_protocol_prefix = PROTO_CFTP_PREFIX;
            break;

        case PROTO_ALN:
            m_protocol_prefix = PROTO_ALN_PREFIX;
            break;

        case PROTO_SAT_EXPAK:
            m_protocol_prefix = PROTO_SAT_EXPAK_PREFIX;
            break;

        case PROTO_KRYPTOLAN:
            m_protocol_prefix = PROTO_KRYPTOLAN_PREFIX;
            break;

        case PROTO_RVD:
            m_protocol_prefix = PROTO_RVD_PREFIX;
            break;

        case PROTO_IPPC:
            m_protocol_prefix = PROTO_IPPC_PREFIX;
            break;

        case PROTO_ADFS:
            m_protocol_prefix = PROTO_ADFS_PREFIX;
            break;

        case PROTO_SAT_MON:
            m_protocol_prefix = PROTO_SAT_MON_PREFIX;
            break;

        case PROTO_VISA:
            m_protocol_prefix = PROTO_VISA_PREFIX;
            break;

        case PROTO_IPCV:
            m_protocol_prefix = PROTO_IPCV_PREFIX;
            break;

        case PROTO_CPNX:
            m_protocol_prefix = PROTO_CPNX_PREFIX;
            break;

        case PROTO_CPHB:
            m_protocol_prefix = PROTO_CPHB_PREFIX;
            break;

        case PROTO_WSN:
            m_protocol_prefix = PROTO_WSN_PREFIX;
            break;

        case PROTO_PVP:
            m_protocol_prefix = PROTO_PVP_PREFIX;
            break;

        case PROTO_BR_SAT_MON:
            m_protocol_prefix = PROTO_BR_SAT_MON_PREFIX;
            break;

        case PROTO_SUN_ND:
            m_protocol_prefix = PROTO_SUN_ND_PREFIX;
            break;

        case PROTO_WB_MON:
            m_protocol_prefix = PROTO_WB_MON_PREFIX;
            break;

        case PROTO_WB_EXPAK:
            m_protocol_prefix = PROTO_WB_EXPAK_PREFIX;
            break;

        case PROTO_ISO_IP:
            m_protocol_prefix = PROTO_ISO_IP_PREFIX;
            break;

        case PROTO_VMTP:
            m_protocol_prefix = PROTO_VMTP_PREFIX;
            break;

        case PROTO_SECURE_VMTP:
            m_protocol_prefix = PROTO_SECURE_VMTP_PREFIX;
            break;

        case PROTO_VINES:
            m_protocol_prefix = PROTO_VINES_PREFIX;
            break;

        case PROTO_IPTM:
            m_protocol_prefix = PROTO_IPTM_PREFIX;
            break;

        case PROTO_NSFNET_IGP:
            m_protocol_prefix = PROTO_NSFNET_IGP_PREFIX;
            break;

        case PROTO_DGP:
            m_protocol_prefix = PROTO_DGP_PREFIX;
            break;

        case PROTO_TCF:
            m_protocol_prefix = PROTO_TCF_PREFIX;
            break;

        case PROTO_EIGRP:
            m_protocol_prefix = PROTO_EIGRP_PREFIX;
            break;

        case PROTO_OSPF:
            m_protocol_prefix = PROTO_OSPF_PREFIX;
            break;

        case PROTO_SPRITE_RPC:
            m_protocol_prefix = PROTO_SPRITE_RPC_PREFIX;
            break;

        case PROTO_LARP:
            m_protocol_prefix = PROTO_LARP_PREFIX;
            break;

        case PROTO_MTP:
            m_protocol_prefix = PROTO_MTP_PREFIX;
            break;

        case PROTO_AX_25:
            m_protocol_prefix = PROTO_AX_25_PREFIX;
            break;

        case PROTO_IPIP:
            m_protocol_prefix = PROTO_IPIP_PREFIX;
            break;

        case PROTO_MICP:
            m_protocol_prefix = PROTO_MICP_PREFIX;
            break;

        case PROTO_SCC_SP:
            m_protocol_prefix = PROTO_SCC_SP_PREFIX;
            break;

        case PROTO_ETHERIP:
            m_protocol_prefix = PROTO_ETHERIP_PREFIX;
            break;

        case PROTO_ENCAP:
            m_protocol_prefix = PROTO_ENCAP_PREFIX;
            break;

        case PROTO_APES:
            m_protocol_prefix = PROTO_APES_PREFIX;
            break;

        case PROTO_GMTP:
            m_protocol_prefix = PROTO_GMTP_PREFIX;
            break;

        case PROTO_IFMP:
            m_protocol_prefix = PROTO_IFMP_PREFIX;
            break;

        case PROTO_PNNI:
            m_protocol_prefix = PROTO_PNNI_PREFIX;
            break;

        case PROTO_PIM:
            m_protocol_prefix = PROTO_PIM_PREFIX;
            break;

        case PROTO_ARIS:
            m_protocol_prefix = PROTO_ARIS_PREFIX;
            break;

        case PROTO_SCPS:
            m_protocol_prefix = PROTO_SCPS_PREFIX;
            break;

        case PROTO_QNX:
            m_protocol_prefix = PROTO_QNX_PREFIX;
            break;

        case PROTO_AN:
            m_protocol_prefix = PROTO_AN_PREFIX;
            break;

        case PROTO_IP_COMP:
            m_protocol_prefix = PROTO_IP_COMP_PREFIX;
            break;

        case PROTO_SNP:
            m_protocol_prefix = PROTO_SNP_PREFIX;
            break;

        case PROTO_COMPAQ:
            m_protocol_prefix = PROTO_COMPAQ_PREFIX;
            break;

        case PROTO_IPX_IN_IP:
            m_protocol_prefix = PROTO_IPX_IN_IP_PREFIX;
            break;

        case PROTO_VRRP:
            m_protocol_prefix = PROTO_VRRP_PREFIX;
            break;

        case PROTO_PGM:
            m_protocol_prefix = PROTO_PGM_PREFIX;
            break;

        case PROTO_AZHP:
            m_protocol_prefix = PROTO_AZHP_PREFIX;
            break;

        case PROTO_L2TP:
            m_protocol_prefix = PROTO_L2TP_PREFIX;
            break;

        case PROTO_DDX:
            m_protocol_prefix = PROTO_DDX_PREFIX;
            break;

        case PROTO_IATP:
            m_protocol_prefix = PROTO_IATP_PREFIX;
            break;

        case PROTO_STP:
            m_protocol_prefix = PROTO_STP_PREFIX;
            break;

        case PROTO_SRP:
            m_protocol_prefix = PROTO_SRP_PREFIX;
            break;

        case PROTO_UTI:
            m_protocol_prefix = PROTO_UTI_PREFIX;
            break;

        case PROTO_SMP:
            m_protocol_prefix = PROTO_SMP_PREFIX;
            break;

        case PROTO_SM:
            m_protocol_prefix = PROTO_SM_PREFIX;
            break;

        case PROTO_PTP:
            m_protocol_prefix = PROTO_PTP_PREFIX;
            break;

        case PROTO_IPv4_ISIS:
            m_protocol_prefix = PROTO_IPv4_ISIS_PREFIX;
            break;

        case PROTO_FIRE:
            m_protocol_prefix = PROTO_FIRE_PREFIX;
            break;

        case PROTO_CRTP:
            m_protocol_prefix = PROTO_CRTP_PREFIX;
            break;

        case PROTO_CRUDP:
            m_protocol_prefix = PROTO_CRUDP_PREFIX;
            break;

        case PROTO_SSCOPMCE:
            m_protocol_prefix = PROTO_SSCOPMCE_PREFIX;
            break;

        case PROTO_IPLT:
            m_protocol_prefix = PROTO_IPLT_PREFIX;
            break;

        case PROTO_SPS:
            m_protocol_prefix = PROTO_SPS_PREFIX;
            break;

        case PROTO_PIPE:
            m_protocol_prefix = PROTO_PIPE_PREFIX;
            break;

        case PROTO_SCTP:
            m_protocol_prefix = PROTO_SCTP_PREFIX;
            break;

        case PROTO_FC:
            m_protocol_prefix = PROTO_FC_PREFIX;
            break;

        case PROTO_RSVP_E2E_IGNORE:
            m_protocol_prefix = PROTO_RSVP_E2E_IGNORE_PREFIX;
            break;

        case PROTO_MH:
            m_protocol_prefix = PROTO_MH_PREFIX;
            break;

        case PROTO_UDPL:
            m_protocol_prefix = PROTO_UDPL_PREFIX;
            break;

        case PROTO_MPLS_IN_IP:
            m_protocol_prefix = PROTO_MPLS_IN_IP_PREFIX;
            break;

        case PROTO_MANET:
            m_protocol_prefix = PROTO_MANET_PREFIX;
            break;

        case PROTO_HIP:
            m_protocol_prefix = PROTO_HIP_PREFIX;
            break;

        case PROTO_SHIM6:
            m_protocol_prefix = PROTO_SHIM6_PREFIX;
            break;

        case PROTO_WESP:
            m_protocol_prefix = PROTO_WESP_PREFIX;
            break;

        case PROTO_ROHC:
            m_protocol_prefix = PROTO_ROHC_PREFIX;
            break;

        default:
            m_protocol_prefix = PROTO_UNKNOWN_PREFIX;
            break;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes start and end value of source IPv4 range based on its prefix representation.
 *
 * Method computes start and end value of source IPv4 range based on its already
 * set prefix representation.
 */
void AclRule::computeSrcIpStartStop()
{
    /* using IP_ADDRESS structure as a 32bit unsigned int, for easier logical operations */
    u_int32_t* const srcIPstart_ptr = (u_int32_t* const) &m_srcIP_start;
    u_int32_t* const srcIPstop_ptr = (u_int32_t* const) &m_srcIP_stop;

    /* set the range to maximum == "any" */
    (*srcIPstart_ptr) = 0x00000000;
    (*srcIPstop_ptr) = 0xFFFFFFFF;
    
    int prefixSize = m_srcIP_prefix.size();
    u_int32_t maska = 0x80000000;               /* mask for setting particular bite from prefix */
    
    /* based on prefix representation we set appropriate parts of start and end IPv4 range */
    for ( int i = 0; i < prefixSize; ++i )
    {
        /* if there is bite "1" on position "i" */
        if ( m_srcIP_prefix[i] )
        {
            (*srcIPstart_ptr) |= maska;
            /* for end (stop) we don't need to set value "1" */
        }
        /* if there is bite "0" on position "i" */
        else
        {
            (*srcIPstop_ptr) &= ~maska;
            /* for start we don't need to set value "0" */
        }

        maska >>= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes start and end value of destination IPv4 range based on its prefix representation.
 *
 * Method computes start and end value of destination IPv4 range based on its already
 * set prefix representation.
 */
void AclRule::computeDstIpStartStop()
{
    /* using IP_ADDRESS structure as a 32bit unsigned int, for easier logical operations */
    u_int32_t* const dstIPstart_ptr = (u_int32_t* const) &m_dstIP_start;
    u_int32_t* const dstIPstop_ptr = (u_int32_t* const) &m_dstIP_stop;

    /* set the range to maximum == "any" */
    (*dstIPstart_ptr) = 0x00000000;
    (*dstIPstop_ptr) = 0xFFFFFFFF;

    int prefixSize = m_dstIP_prefix.size();
    u_int32_t maska = 0x80000000;               /* mask for setting particular bite from prefix */

    /* based on prefix representation we set appropriate parts of start and end IPv4 range */
    for ( int i = 0; i < prefixSize; ++i )
    {
        /* if there is bite "1" on position "i" */
        if ( m_dstIP_prefix[i] )
        {
            (*dstIPstart_ptr) |= maska;
            /* for end (stop) we don't need to set value "1" */
        }
        /* if there is bite "0" on position "i" */
        else
        {
            (*dstIPstop_ptr) &= ~maska;
            /* for start we don't need to set value "0" */
        }

        maska >>= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes start and end value of source port (TCP/UDP) range based on its prefix representation.
 *
 * Method computes start and end value of source port range based on its already
 * set prefix representation.
 */
void AclRule::computeSrcPortStartStop()
{
    /* set the range to maximum == "any" */
    m_srcPort_start = 0x0000;
    m_srcPort_stop = 0xFFFF;

    int prefixSize = m_srcPort_prefix.size();
    u_int16_t maska = 0x8000;                   /* mask for setting particular bite from prefix */

    /* based on prefix representation we set appropriate parts of start and end port range */
    for ( int i = 0; i < prefixSize; ++i )
    {
        /* if there is bite "1" on position "i" */
        if ( m_srcPort_prefix[i] )
        {
            m_srcPort_start |= maska;
            /* for end (stop) we don't need to set value "1" */
        }
        /* if there is bite "0" on position "i" */
        else
        {
            m_srcPort_stop &= ~maska;
            /* for start we don't need to set value "0" */
        }

        maska >>= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method computes start and end value of destination port (TCP/UDP) range based on its prefix representation.
 *
 * Method computes start and end value of destination port range based on its already
 * set prefix representation.
 */
void AclRule::computeDstPortStartStop()
{
    /* set the range to maximum == "any" */
    m_dstPort_start = 0x0000;
    m_dstPort_stop = 0xFFFF;

    int prefixSize = m_dstPort_prefix.size();
    u_int16_t maska = 0x8000;                   /* mask for setting particular bite from prefix */

    /* based on prefix representation we set appropriate parts of start and end port range */
    for ( int i = 0; i < prefixSize; ++i )
    {
        /* if there is bite "1" on position "i" */
        if ( m_dstPort_prefix[i] )
        {
            m_dstPort_start |= maska;
            /* for end (stop) we don't need to set value "1" */
        }
        /* if there is bite "0" on position "i" */
        else
        {
            m_dstPort_stop &= ~maska;
            /* for start we don't need to set value "0" */
        }

        maska >>= 1;
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method translates passed protocol number to a string.
 *
 * @param protocol IP protocol number (should be constant PROTO_xxx).
 * @return string representing protocol passed as previous parameter.
 */
string AclRule::protocolToString(int protocol)
{
    switch ( protocol )
    {
        case PROTO_ANY:
            return string("any");

        case PROTO_IPv4:
            return string("ip");

        case PROTO_ICMPv4:
            return string("icmp");

        case PROTO_TCP:
            return string("tcp");

        case PROTO_UDP:
            return string("udp");

        case PROTO_AH:
            return string("ahp");

        case PROTO_GRE:
            return string("gre");

        case PROTO_IP_IN_IP:
            return string("ipinip");

        case PROTO_OSPF:
            return string("ospf");

        case PROTO_PIM:
            return string("pim");

        case PROTO_ESP:
            return string("esp");

        case PROTO_EIGRP:
            return string("eigrp");

        case PROTO_IGMP:
            return string("igmp");

        case PROTO_VRRP:
            return string("vrrp");

        case PROTO_L2TP:
            return string("l2tp");

        case PROTO_SCTP:
            return string("sctp");
            
        default:
            stringstream ss;
            ss << protocol;
            return ss.str();
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method translates passed port (TCP/UDP) number to a string.
 *
 * @param port value representing particular TCP/UDP port number (should be constant PORT_xxx).
 * @return string representing port number passed as previous parameter.
 */
string AclRule::portToString(u_int16_t port)
{
    switch ( port )
    {
        case PORT_ECHO:
            return string("echo");

        case PORT_DISCARD:
            return string("discard");

        case PORT_DAYTIME:
            return string("daytime");

        case PORT_CHARGEN:
            return string("chargen");

        case PORT_FTP_DATA:
            return string("ftp_data");

        case PORT_FTP:
            return string("ftp");

        case PORT_TELNET:
            return string("telnet");

        case PORT_SMTP:
            return string("smtp");

        case PORT_TIME:
            return string("time");

        case PORT_NAMESERVER:
            return string("nameserver");

        case PORT_WHOIS:
            return string("whois");

        case PORT_TACACS:
            return string("tacacs");

        case PORT_DOMAIN:
            return string("domain");

        case PORT_BOOTPC:
            return string("bootpc");

        case PORT_TFTP:
            return string("tftp");

        case PORT_GOPHER:
            return string("gopher");

        case PORT_FINGER:
            return string("finger");

        case PORT_WWW:
            return string("http");

        case PORT_HOSTNAME:
            return string("hostname");

        case PORT_POP2:
            return string("pop2");

        case PORT_POP3:
            return string("pop3");

        case PORT_SUNRPC:
            return string("sunrpc");

        case PORT_IDENT:
            return string("ident");

        case PORT_NNTP:
            return string("nntp");

        case PORT_NTP:
            return string("ntp");

        case PORT_NETBIOS_NS:
            return string("netbios_ns");

        case PORT_NETBIOS_DGM:
            return string("netbios_dgm");

        case PORT_NETBIOS_SS:
            return string("netbios_ss");

        case PORT_SNMP:
            return string("snmp");

        case PORT_SNMPTRAP:
            return string("snmptrap");

        case PORT_XDMCP:
            return string("xdmcp");

        case PORT_BGP:
            return string("bgp");

        case PORT_IRC:
            return string("irc");

        case PORT_DNSIX:
            return string("dnsix");

        case PORT_MOBILE_IP:
            return string("mobile_ip");

        case PORT_PIM_AUTO_RP:
            return string("pim_auto_rp");

        case PORT_ISAKMP:
            return string("isakmp");

        case PORT_LPD:
            return string("lpd");

        case PORT_TALK:
            return string("talk");

        case PORT_RIP:
            return string("rip");

        case PORT_UUCP:
            return string("uucp");

        case PORT_KLOGIN:
            return string("klogin");

        case PORT_KSHELL:
            return string("kshell");

        case PORT_NON500_ISAKMP:
            return string("non500_isakmp");

        default:
            stringstream ss;
            ss << port;
            return ss.str();
    }
}

//-----------------------------------------------------------------------------------

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
ostream& operator<<(ostream& out, const AclRule& rule)
{
    out << rule.getActionString();
    out << " proto=\"" << rule.getProtocolString() << "\" ";
    out << "srcIP=\"" << rule.getSrcIpRangeString() << "\" ";

    if ( (rule.getProtocol() == PROTO_TCP) || (rule.getProtocol() == PROTO_UDP) )
    {
        if ( rule.getSrcPortNeg() )
            out << "srcPort=\"not(" << rule.getSrcPortRangeString() << ")\" ";
        else
            out << "srcPort=\"" << rule.getSrcPortRangeString() << "\" ";
    }

    out << "dstIP=\"" << rule.getDstIpRangeString() << "\" ";

    if ( (rule.getProtocol() == PROTO_TCP) || (rule.getProtocol() == PROTO_UDP) )
    {
        if ( rule.getDstPortNeg() )
            out << "dstPort=\"not(" << rule.getDstPortRangeString() << ")\"";
        else
            out << "dstPort=\"" << rule.getDstPortRangeString() << "\"";
    }

    return out;
}

/*******************************************************************************/
/********************************* GET Methods *********************************/

/**
 * Method for getting string representation of source IPv4 address range.
 *
 * Method returns string representation of source IPv4 address range
 * in the form of "x.x.x.x-y.y.y.y" or in the form of "x.x.x.x" if start
 * and end IPv4 address are the same, or key-word "any" representing
 * address range of "0.0.0.0-255.255.255.255".
 *
 * @return string representation of source IPv4 address range.
 */
string AclRule::getSrcIpRangeString() const
{
    if ( (*((u_int32_t*) &m_srcIP_start) == 0x00000000) && (*((u_int32_t*) &m_srcIP_stop) == 0xFFFFFFFF) )
    {
        return string("any");
    }
    else
    {
        char buffer[32];
        if ( *((u_int32_t*)&m_srcIP_start) == *((u_int32_t*)&m_srcIP_stop) )
        {
            sprintf(buffer, "%u.%u.%u.%u", m_srcIP_start.A, m_srcIP_start.B, m_srcIP_start.C, m_srcIP_start.D);
        }
        else
        {
            sprintf(buffer, "%u.%u.%u.%u-%u.%u.%u.%u", m_srcIP_start.A, m_srcIP_start.B, m_srcIP_start.C, m_srcIP_start.D, m_srcIP_stop.A, m_srcIP_stop.B, m_srcIP_stop.C, m_srcIP_stop.D);
        }
        
        return string(buffer);
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting start address of source IPv4 address range.
 *
 * Method for getting reference to IP_ADDRESS structure containing
 * start address of source IPv4 address range.
 *
 * @return reference to the IP_ADDRESS structure containing start
 *         address of source IPv4 address range.
 */
const IP_ADDRESS& AclRule::getSrcIpStart() const
{
    return m_srcIP_start;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting end address of source IPv4 address range.
 *
 * Method for getting reference to IP_ADDRESS structure containing
 * end address of source IPv4 address range.
 *
 * @return reference to the IP_ADDRESS structure containing end
 *         address of source IPv4 address range.
 */
const IP_ADDRESS& AclRule::getSrcIpStop() const
{
    return m_srcIP_stop;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting prefix representation of the source IPv4 address range.
 *
 * Method for getting reference to boost::dynamic_bitset<> object containing
 * prefix representation of the source IPv4 address range.
 *
 * @return reference to the boost::dynamic_bitset<> object containing
 *         prefix representation of the source IPv4 address range.
 */
const boost::dynamic_bitset< >& AclRule::getSrcIpPrefix() const
{
    return m_srcIP_prefix;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string representation of destination IPv4 address range.
 *
 * Method returns string representation of destination IPv4 address range
 * in the form of "x.x.x.x-y.y.y.y" or in the form of "x.x.x.x" if start
 * and end IPv4 address are the same, or key-word "any" representing
 * address range of "0.0.0.0-255.255.255.255".
 *
 * @return string representation of destination IPv4 address range.
 */
string AclRule::getDstIpRangeString() const
{
    if ( (*((u_int32_t*) &m_dstIP_start) == 0x00000000) && (*((u_int32_t*) &m_dstIP_stop) == 0xFFFFFFFF) )
    {
        return string("any");
    }
    else
    {
        char buffer[32];
        if ( *((u_int32_t*)&m_dstIP_start) == *((u_int32_t*)&m_dstIP_stop) )
        {
            sprintf(buffer, "%u.%u.%u.%u", m_dstIP_start.A, m_dstIP_start.B, m_dstIP_start.C, m_dstIP_start.D);
        }
        else
        {
            sprintf(buffer, "%u.%u.%u.%u-%u.%u.%u.%u", m_dstIP_start.A, m_dstIP_start.B, m_dstIP_start.C, m_dstIP_start.D, m_dstIP_stop.A, m_dstIP_stop.B, m_dstIP_stop.C, m_dstIP_stop.D);
        }

        return string(buffer);
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting start address of destination IPv4 address range.
 *
 * Method for getting reference to IP_ADDRESS structure containing
 * start address of destination IPv4 address range.
 *
 * @return reference to the IP_ADDRESS structure containing start
 *         address of destination IPv4 address range.
 */
const IP_ADDRESS& AclRule::getDstIpStart() const
{
    return m_dstIP_start;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting end address of destination IPv4 address range.
 *
 * Method for getting reference to IP_ADDRESS structure containing
 * end address of destination IPv4 address range.
 *
 * @return reference to the IP_ADDRESS structure containing end
 *         address of destination IPv4 address range.
 */
const IP_ADDRESS& AclRule::getDstIpStop() const
{
    return m_dstIP_stop;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting prefix representation of the destination IPv4 address range.
 *
 * Method for getting reference to boost::dynamic_bitset<> object containing
 * prefix representation of the destination IPv4 address range.
 *
 * @return reference to the boost::dynamic_bitset<> object containing
 *         prefix representation of the destination IPv4 address range.
 */
const boost::dynamic_bitset< >& AclRule::getDstIpPrefix() const
{
    return m_dstIP_prefix;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string representation of source port (TCP/UDP) range.
 *
 * Method returns string representation of source TCP/UDP port range
 * in the form of "xxx-yyy", where "xxx" and "yyy" is a port number
 * or key-word representing some well-known port number. If start
 * and end port number of the port range are the same, then method
 * returns string "xxx" or key-word representing some well-known port 
 * number. In case of port range of "0-65535" key-word "any" is returned.
 *
 * @return string representation of source port range.
 */
string AclRule::getSrcPortRangeString() const
{
    if ( (m_srcPort_start == 0x0000) && (m_srcPort_stop == 0xFFFF) )
    {
        return string("any");
    }
    else
    {
        if ( m_srcPort_start == m_srcPort_stop )
        {
            return portToString(m_srcPort_start);
        }
        else
        {
            stringstream tmp_strStream;
            tmp_strStream << portToString(m_srcPort_start) << "-" << portToString(m_srcPort_stop);
            return tmp_strStream.str();
        }
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting start port number of source port (TCP/UDP) range.
 *
 * Method returns start port number of source TCP/UDP port range.
 *
 * @return start port number of source port range.
 */
u_int16_t AclRule::getSrcPortStart() const
{
    return m_srcPort_start;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting end port number of source port (TCP/UDP) range.
 *
 * Method returns end port number of source TCP/UDP port range.
 *
 * @return end port number of source port range.
 */
u_int16_t AclRule::getSrcPortStop() const
{
    return m_srcPort_stop;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting prefix representation of the source port (TCP/UDP) range.
 *
 * Method for getting reference to boost::dynamic_bitset<> object containing
 * prefix representation of the source port (TCP/UDP) range.
 *
 * @return reference to the boost::dynamic_bitset<> object containing
 *         prefix representation of the source port (TCP/UDP) range.
 */
const boost::dynamic_bitset< >& AclRule::getSrcPortPrefix() const
{
    return m_srcPort_prefix;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting flag representing if the source port range is negated/inverted.
 *
 * Method returns boolean value representing whether the source TCP/UDP port range
 * is negated/inverted or not.
 *
 * @return TRUE - if the source port range is negated/inverted.
 *         FALSE - if the source port range is NOT negated/inverted.
 */
bool AclRule::getSrcPortNeg() const
{
    return m_srcPortNeg;
}

//-----------------------------------------------------------------------------------

/**
 * Method returns string representation of destination port (TCP/UDP) range.
 *
 * Method returns string representation of destination TCP/UDP port range
 * in the form of "xxx-yyy", where "xxx" and "yyy" is a port number
 * or key-word representing some well-known port number. If start
 * and end port number of the port range are the same, then method
 * returns string "xxx" or key-word representing some well-known port 
 * number. In case of port range of "0-65535" key-word "any" is returned.
 *
 * @return string representation of destination port range.
 */
string AclRule::getDstPortRangeString() const
{
    if ( (m_dstPort_start == 0x0000) && (m_dstPort_stop == 0xFFFF) )
    {
        return string("any");
    }
    else
    {
        if ( m_dstPort_start == m_dstPort_stop )
        {
            return portToString(m_dstPort_start);
        }
        else
        {
            stringstream tmp_strStream;
            tmp_strStream << portToString(m_dstPort_start) << "-" << portToString(m_dstPort_stop);
            return tmp_strStream.str();
        }
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting start port number of destination port (TCP/UDP) range.
 *
 * Method returns start port number of destination TCP/UDP port range.
 *
 * @return start port number of destination port range.
 */
u_int16_t AclRule::getDstPortStart() const
{
    return m_dstPort_start;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting end port number of destination port (TCP/UDP) range.
 *
 * Method returns end port number of destination TCP/UDP port range.
 *
 * @return end port number of destination port range.
 */
u_int16_t AclRule::getDstPortStop() const
{
    return m_dstPort_stop;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting prefix representation of the destination port (TCP/UDP) range.
 *
 * Method for getting reference to boost::dynamic_bitset<> object containing
 * prefix representation of the destination port (TCP/UDP) range.
 *
 * @return reference to the boost::dynamic_bitset<> object containing
 *         prefix representation of the destination port (TCP/UDP) range.
 */
const boost::dynamic_bitset< >& AclRule::getDstPortPrefix() const
{
    return m_dstPort_prefix;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting flag representing if the destination port range is negated/inverted.
 *
 * Method returns boolean value representing whether the destination TCP/UDP port range
 * is negated/inverted or not.
 *
 * @return TRUE - if the destination port range is negated/inverted.
 *         FALSE - if the destination port range is NOT negated/inverted.
 */
bool AclRule::getDstPortNeg() const
{
    return m_dstPortNeg;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string representing set protocol.
 *
 * Method returns string containing set protocol number or a key-word
 * representing set protocol.
 *
 * @return string representing set protocol.
 */
string AclRule::getProtocolString() const
{
    return protocolToString(m_protocol);
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting set protocol number.
 *
 * Method returns number of set protocol. Returned value should have value
 * of some existing PROTO_xxx constant.
 *
 * @return set protocol number.
 */
int AclRule::getProtocol() const
{
    return m_protocol;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting prefix representation of the set protocol.
 *
 * Method for getting reference to boost::dynamic_bitset<> object containing
 * prefix representation of the set protocol.
 *
 * @return reference to the boost::dynamic_bitset<> object containing
 *         prefix representation of the set protocol.
 */
const boost::dynamic_bitset< >& AclRule::getProtocolPrefix() const
{
    return m_protocol_prefix;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string representation of the rule action.
 *
 * @return "permit" - if the action is to permit matching packets.
 *         "deny" - if the action is to deny matching packets.
 */
string AclRule::getActionString() const
{
    if ( m_action == ACTION_ALLOW )
        return string("permit");
    else
        return string("deny");
}

//-----------------------------------------------------------------------------------

/**
 * Method gor getting value representing action of the rule.
 *
 * @return ACTION_ALLOW - if the action is to permit matching packets.
 *         ACTION_DENY - if the action is to deny matching packets.
 */
int AclRule::getAction() const
{
    return m_action;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting position of the rule in ACL.
 *
 * @return position of the rule in ACL.
 */
unsigned int AclRule::getPosition() const
{
    return m_rulePositionNumber;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string containing the rule name (ID).
 *
 * @return string containing rule the rule name (ID).
 */
string AclRule::getName() const
{
    return m_name;
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting string representation of wanted dimension (field).
 *
 * Method returns string representation of particular dimension (field)
 * specified by passed value (should be entered as constant DIMENSION_xxx).
 *
 * @throw Exception if unknown dimension number is passed as parameter, method
 *                  throws exception "Unknown dimension! Out of borders!".
 * @param dimension value representing wanted dimension (field). Should be constant DIMENSION_xxx.
 * @return string representation of wanted dimension (field).
 */
string AclRule::getFieldString(int dimension) const throw(Exception)
{
    switch ( dimension )
    {
        case DIMENSION_PROTO:
            return getProtocolString();

        case DIMENSION_SRC_IP:
            return getSrcIpRangeString();

        case DIMENSION_DST_IP:
            return getDstIpRangeString();

        case DIMENSION_SRC_PRT:
            return getSrcPortRangeString();

        case DIMENSION_DST_PRT:
            return getDstPortRangeString();

        default:
            throw Exception("Unknown dimension! Out of borders!");
    }
}

//-----------------------------------------------------------------------------------

/**
 * Method for getting reference to object containing prefix representation of wanted dimension (field).
 *
 * Method returns reference to boost::dynamic_bitset<> object containing
 * prefix representation of particular dimension (field) specified by
 * passed value (should be entered as constant DIMENSION_xxx).
 *
 * @throw Exception if unknown dimension number is passed as parameter, method
 *                  throws exception "Unknown dimension! Out of borders!".
 * @param dimension value representing wanted dimension (field). Should be constant DIMENSION_xxx.
 * @return reference to boost::dynamic_bitset<> object containing prefix
 *         representation of wanted dimension (field).
 */
const boost::dynamic_bitset< >& AclRule::getFieldPrefix(int dimension) const throw(Exception)
{
    switch ( dimension )
    {
        case DIMENSION_PROTO:
            return m_protocol_prefix;

        case DIMENSION_SRC_IP:
            return m_srcIP_prefix;

        case DIMENSION_DST_IP:
            return m_dstIP_prefix;

        case DIMENSION_SRC_PRT:
            return m_srcPort_prefix;

        case DIMENSION_DST_PRT:
            return m_dstPort_prefix;

        default:
            throw Exception("Unknown dimension! Out of borders!");
    }
}

/*******************************************************************************/
/********************************* SET Methods *********************************/

/**
 * Method for setting source IPv4 address range.
 *
 * Method allows to set source IPv4 address range by specifying
 * start and end address of the source address range. Method assumes
 * IPv4 addresses entered in dotted decimal form "A.B.C.D".
 * Method automatically computes prefix form, if not set otherwise.
 *
 * @param startA value representing "A" portion of start address.
 * @param startB value representing "B" portion of start address.
 * @param startC value representing "C" portion of start address.
 * @param startD value representing "D" portion of start address.
 * @param stopA value representing "A" portion of end address.
 * @param stopB value representing "B" portion of end address.
 * @param stopC value representing "C" portion of end address.
 * @param stopD value representing "D" portion of end address.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set address range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setSrcIP(u_int8_t startA, u_int8_t startB, u_int8_t startC, u_int8_t startD, u_int8_t stopA, u_int8_t stopB, u_int8_t stopC, u_int8_t stopD, bool compute_prefix)
{
    m_srcIP_start.A = startA;
    m_srcIP_start.B = startB;
    m_srcIP_start.C = startC;
    m_srcIP_start.D = startD;

    m_srcIP_stop.A = stopA;
    m_srcIP_stop.B = stopB;
    m_srcIP_stop.C = stopC;
    m_srcIP_stop.D = stopD;

    if ( compute_prefix )
        computeSrcIpPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting source IPv4 address range.
 *
 * Method allows to set source IPv4 address range by specifying
 * start and end address of the source address range. Method assumes
 * IPv4 addresses entered as reference to IP_ADDRESS structure.
 * Method automatically computes prefix form, if not set otherwise.
 *
 * @param start reference to IP_ADDRESS structure containing start address.
 * @param stop reference to IP_ADDRESS structure containing end address.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set address range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setSrcIP(const IP_ADDRESS& start, const IP_ADDRESS& stop, bool compute_prefix)
{
    m_srcIP_start = start;
    m_srcIP_stop = stop;

    if ( compute_prefix )
        computeSrcIpPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting prefix form of source IPv4 address range.
 *
 * Method allows to set prefix form of source IPv4 address range 
 * by specifying it using boost::dynamic_bitset< > object.
 * Method automatically computes start and end address of address
 * range from entered prefix, if not set otherwise.
 *
 * @param srcIPprefix reference to a boost::dynamic_bitset< > object containing
 *                    prefix form of address range.
 * @param compute_start_stop flag setting if method automatically computes
 *                           start and end address of address range. Default 
 *                           value of this parameter is TRUE, which means 
 *                           that addresses are automatically computed.
 */
void AclRule::setSrcIP(const boost::dynamic_bitset< >& srcIPprefix, bool compute_start_stop)
{
    m_srcIP_prefix = srcIPprefix;

    if ( compute_start_stop )
        computeSrcIpStartStop();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting destination IPv4 address range.
 *
 * Method allows to set destination IPv4 address range by specifying
 * start and end address of the destination address range. Method assumes
 * IPv4 addresses entered in dotted decimal form "A.B.C.D".
 * Method automatically computes prefix form, if not set to otherwise.
 *
 * @param startA value representing "A" portion of start address.
 * @param startB value representing "B" portion of start address.
 * @param startC value representing "C" portion of start address.
 * @param startD value representing "D" portion of start address.
 * @param stopA value representing "A" portion of end address.
 * @param stopB value representing "B" portion of end address.
 * @param stopC value representing "C" portion of end address.
 * @param stopD value representing "D" portion of end address.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set address range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setDstIP(u_int8_t startA, u_int8_t startB, u_int8_t startC, u_int8_t startD, u_int8_t stopA, u_int8_t stopB, u_int8_t stopC, u_int8_t stopD, bool compute_prefix)
{
    m_dstIP_start.A = startA;
    m_dstIP_start.B = startB;
    m_dstIP_start.C = startC;
    m_dstIP_start.D = startD;

    m_dstIP_stop.A = stopA;
    m_dstIP_stop.B = stopB;
    m_dstIP_stop.C = stopC;
    m_dstIP_stop.D = stopD;

    if ( compute_prefix )
        computeDstIpPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting destination IPv4 address range.
 *
 * Method allows to set destination IPv4 address range by specifying
 * start and end address of the destination address range. Method assumes
 * IPv4 addresses entered as reference to IP_ADDRESS structure.
 * Method automatically computes prefix form, if not set otherwise.
 *
 * @param start reference to IP_ADDRESS structure containing start address.
 * @param stop reference to IP_ADDRESS structure containing end address.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set address range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setDstIP(const IP_ADDRESS& start, const IP_ADDRESS& stop, bool compute_prefix)
{
    m_dstIP_start = start;
    m_dstIP_stop = stop;

    if ( compute_prefix )
        computeDstIpPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting prefix form of destination IPv4 address range.
 *
 * Method allows to set prefix form of destination IPv4 address range 
 * by specifying it using boost::dynamic_bitset< > object.
 * Method automatically computes start and end address of address
 * range from entered prefix, if not set otherwise.
 *
 * @param dstIPprefix reference to a boost::dynamic_bitset< > object containing
 *                    prefix form of address range.
 * @param compute_start_stop flag setting if method automatically computes
 *                           start and end address of address range. Default 
 *                           value of this parameter is TRUE, which means 
 *                           that addresses are automatically computed.
 */
void AclRule::setDstIP(const boost::dynamic_bitset< >& dstIPprefix, bool compute_start_stop)
{
    m_dstIP_prefix = dstIPprefix;

    if ( compute_start_stop )
        computeDstIpStartStop();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting source port (TCP/UDP) range.
 *
 * Method allows to set source TCP/UDP port range by specifying
 * start and end port number of the source port range. Method allows
 * to set flag if specified port range is negated/inverted.
 * Method automatically computes prefix form, if not set otherwise.
 *
 * @param start start port of the port range.
 * @param stop end port of the port range.
 * @param negated flag if specified port range is negated/inverted. 
 *                Default value of this parameter is FALSE.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set port range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setSrcPort(u_int16_t start, u_int16_t stop, bool negated, bool compute_prefix)
{
    m_srcPortNeg = negated;
    m_srcPort_start = start;
    m_srcPort_stop = stop;

    if ( compute_prefix )
        computeSrcPortPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting prefix form of source (TCP/UDP) port range.
 *
 * Method allows to set prefix form of source TCP/UDP port range 
 * by specifying it using boost::dynamic_bitset< > object.
 * Method automatically computes start and end port number of port
 * range from entered prefix, if not set otherwise.
 *
 * @param srcPortPrefix reference to a boost::dynamic_bitset< > object containing
 *                      prefix form of port range.
 * @param compute_start_stop flag setting if method automatically computes
 *                           start and end port number of port range. Default 
 *                           value of this parameter is TRUE, which means 
 *                           that port numbers are automatically computed.
 */
void AclRule::setSrcPort(const boost::dynamic_bitset< >& srcPortPrefix, bool compute_start_stop)
{
    m_srcPortNeg = false;
    m_srcPort_prefix = srcPortPrefix;

    if ( compute_start_stop )
        computeSrcPortStartStop();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting destination port (TCP/UDP) range.
 *
 * Method allows to set destination TCP/UDP port range by specifying
 * start and end port number of the destination port range. Method allows
 * to set flag if specified port range is negated/inverted.
 * Method automatically computes prefix form, if not set otherwise.
 *
 * @param start start port of the port range.
 * @param stop end port of the port range.
 * @param negated flag if specified port range is negated/inverted. 
 *                Default value of this parameter is FALSE.
 * @param compute_prefix flag setting if method automatically computes
 *                       prefix form of set port range. Default value
 *                       of this parameter is TRUE, which means that
 *                       prefix form is automatically computed.
 */
void AclRule::setDstPort(u_int16_t start, u_int16_t stop, bool negated, bool compute_prefix)
{
    m_dstPortNeg = negated;
    m_dstPort_start = start;
    m_dstPort_stop = stop;

    if ( compute_prefix )
        computeDstPortPrefix();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting prefix form of destination (TCP/UDP) port range.
 *
 * Method allows to set prefix form of destination TCP/UDP port range 
 * by specifying it using boost::dynamic_bitset< > object.
 * Method automatically computes start and end port number of port
 * range from entered prefix, if not set otherwise.
 *
 * @param dstPortPrefix reference to a boost::dynamic_bitset< > object containing
 *                      prefix form of port range.
 * @param compute_start_stop flag setting if method automatically computes
 *                           start and end port number of port range. Default 
 *                           value of this parameter is TRUE, which means 
 *                           that port numbers are automatically computed.
 */
void AclRule::setDstPort(const boost::dynamic_bitset< >& dstPortPrefix, bool compute_start_stop)
{
    m_dstPortNeg = false;
    m_dstPort_prefix = dstPortPrefix;

    if ( compute_start_stop )
        computeDstPortStartStop();
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting protocol.
 *
 * Method allows to set protocol by value.
 * Protocol can be set by entering constant PROTO_xxx
 * or by entering number value in range from PROTO__MIN to PROTO__MAX.
 * Method automatically computes prefix form of set protocol.
 *
 * @param protocol value representing protocol.
 * @return 1 - there was some error and protocol is not set.
 *         0 - setting protocol finished successfuly.
 */
int AclRule::setProtocol(int protocol)
{
    /* check if protocol number is valid */
    if ( (protocol < PROTO__MIN) || (protocol > PROTO__MAX) )
        return 1;

    m_protocol = protocol;
    computeProtoPrefix();
    
    return 0;
}

//-----------------------------------------------------------------------------------

/**
 * Method for setting rule action.
 *
 * Method allows to set rule action. Action has to be
 * entered as constant ACTION_ALLOW or ACTION_DENY.
 *
 * @param action value representing rule action (ACTION_ALLOW or ACTION_DENY).
 * @return 1 - there was some error and action is not set.
 *         0 - setting action finished successfuly.
 */
int AclRule::setAction(int action)
{
    /* check if action is valid */
    if ( (action != ACTION_ALLOW) && (action != ACTION_DENY) )
    {
        cout << "set Action error -> " << action << endl;
        return 1;
    }

    m_action = action;
    
    return 0;
}