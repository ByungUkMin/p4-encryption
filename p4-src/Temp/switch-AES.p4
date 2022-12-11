/*****************************************************************************
 *
 *     This file is part of Purdue CS 536.
 *
 *     Purdue CS 536 is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Purdue CS 536 is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Purdue CS 536. If not, see <https://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#define COPYRIGHT_STRING 0xA9204147504c7633
/* -*- P4_16 -*- */
#include <core.p4>
#include <psa.p4>
//#include <v1model.p4>
//#include <tna.p4>

#define MCAST_ID 1
#define CPU_PORT 255
/*
  255 is confirmed for opennetworking/p4mn　(Mininet/Stratum on docker)
  192 is confirmed for WEDGE-100BF-32X (2 pipes device)
  320 is probably good for 4 pipes devices
*/

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_VLAN 0x8100


typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;



//AES variables start

#define AES_PORT 5555

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
typedef bit<32> ipv4_addr_t;

const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

//AES variables end


/**************************************************************************/
/**************************  Headers  *************************************/
/**************************************************************************/

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header vlan_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> etherType;
}

//struct metadata {
//    bit<12> vid;
//    bit<16> etherType;
//    bit<4> _pad;
//}

/**************************************************************************/
/***************************  AES Header + structs  *************************************/
/**************************************************************************/

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header aes_inout_h {
    bit<8> s00;
    bit<8> s01;
    bit<8> s02;
    bit<8> s03;
    bit<8> s10;
    bit<8> s11;
    bit<8> s12;
    bit<8> s13;
    bit<8> s20;
    bit<8> s21;
    bit<8> s22;
    bit<8> s23;
    bit<8> s30;
    bit<8> s31;
    bit<8> s32;
    bit<8> s33;
}
header aes_meta_h {
    bit<16> dest_port;
    bit<8> curr_round;
    bit<8> ff;
}
header copyright_h {
    bit<64> copy;
}

header aes_tmp_h {
    bit<32> v00;
    bit<32> v01;
    bit<32> v02;
    bit<32> v03;
    bit<32> v10;
    bit<32> v11;
    bit<32> v12;
    bit<32> v13;
    bit<32> v20;
    bit<32> v21;
    bit<32> v22;
    bit<32> v23;
    bit<32> v30;
    bit<32> v31;
    bit<32> v32;
    bit<32> v33;
    
    bit<32> s0a;
    bit<32> s1a;
    bit<32> s2a;
    bit<32> s3a;
    bit<32> s0b;
    bit<32> s1b;
    bit<32> s2b;
    bit<32> s3b;
}

struct ig_metadata_t {
    bool recirc;
    
    bit<9> rnd_port_for_recirc;
    bit<1> rnd_bit;

    aes_tmp_h aes_tmp;
}

struct metadata {
    bit<12> vid;
    bit<16> etherType;
    bit<4> _pad;

    // From AES
    ig_metadata_t ig_md;

    bit<9> ingress_port;
}

struct eg_metadata_t {
}


struct headers {
    // From AES
    ethernet_t ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    aes_inout_h aes;
    aes_meta_h aes_meta;
    copyright_h copy;

    // From the assignment3
    vlan_t vlan;
    packet_in_header_t packet_in;
}

struct empty_metadata_t {
}

/**************************************************************************/
/***************************  Ingress Parser  *************************************/
/**************************************************************************/
// struct empty_metadata_t {
// }
// 
// struct fwd_metadata_t {
// }
// 
// struct metadata_t {
//     fwd_metadata_t fwd_metadata;
// }
// parser IngressParserImpl(packet_in buffer,
//                          out headers_t parsed_hdr,
//                          inout metadata_t user_meta,
//                          in psa_ingress_parser_input_metadata_t istd,
//                          in empty_metadata_t resubmit_meta,
//                          in empty_metadata_t recirculate_meta)

parser SwitchIngressParser(packet_in packet,
                	   out headers hdr,
                	   inout metadata meta,
			   in psa_ingress_parser_input_metadata_t istd,
                           in empty_metadata_t resubmit_meta,
                           in empty_metadata_t recirculate_meta) {

    state start {
        transition select(istd.packet_path) {
           PSA_PacketPath_t.RESUBMIT: parse_resubmit;
           PSA_PacketPath_t.NORMAL: parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        packet.advance(64); 
        //pkt.extract(ig_md.resubmit_data_read);
        //transition accept;
        transition parse_ethernet;
    }

    state parse_port_metadata {
        packet.advance(64);  //tofino 1 port metadata size
        //transition accept;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.vid = 0;
        meta.etherType = hdr.ethernet.etherType;
        transition select (hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETH_TYPE_VLAN: parse_vlan; // we're not going here yet
            default : reject;
            //default : accept;
        }
    }

    // Byounguk: How to enable vlan & encryption?
    state parse_vlan {
        packet.extract(hdr.vlan);
        meta.vid = hdr.vlan.vid;
        meta.etherType = hdr.vlan.etherType;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            AES_PORT: parse_aes;
            AES_PORT+1: parse_aes_and_meta;
            default: accept;
        }
    }
    
    state parse_aes {
        packet.extract(hdr.aes);
        transition accept;
    }

    state parse_aes_and_meta {
        packet.extract(hdr.aes);
        packet.extract(hdr.aes_meta);
        transition accept;
    }
}

/**************************************************************************/
/***************************  Ingress  *************************************/
/**************************************************************************/

//control ingress(inout headers_t hdr,
//                inout metadata_t user_meta,
//                in    psa_ingress_input_metadata_t  istd,
//                inout psa_ingress_output_metadata_t ostd)

control SwitchIngress(
	inout headers hdr,
        inout metadata meta,
        in    psa_ingress_input_metadata_t  istd,
        inout psa_ingress_output_metadata_t ostd) {

    // AES Processing starts from here!
    action drop() {
        //ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
        //mark_to_drop(standard_metadata);
	ingress_drop(ostd);
    }
    action nop() {

    }
    // Byounguk: Not used in the original p4 as well
    //action reflect(){
    //    //ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port;
    //    ig_intr_tm_md.ucast_egress_port=standard_metadata.ingress_port;
    //}
    // Byounguk: Let's assume this is same as forward action from the assignment3
    action route_to(bit<9> port) {
        //ig_intr_tm_md.ucast_egress_port=port;
        //standard_metadata.egress_spec = port;
	send_to_port(ostd, port);
    }
    
    // Randomly select one of the two recirc ports
    Random< bit<1> >() rng;
    action get_rnd_bit(){
        meta.ig_md.rnd_bit=rng.get();
        //ig_md.rnd_bit=1;
    }
    
    action do_recirculate(){
        route_to(meta.ig_md.rnd_port_for_recirc);
    }

    
    #define GEN_LOOKUP_TABLE(R,C)     \
    action write_v_## R ##_## C ##_a(bit<32> v){  \
        meta.ig_md.aes_tmp.v## R ## C =v;              \
    } \
    table tb_lookup_## R ##_## C ##_t {           \
        key = {  \
            hdr.aes.s## R ## C : exact;  \
            hdr.aes_meta.curr_round: exact;       \
        } \
        size = 3600; \
        actions = {  \
            write_v_## R ##_## C ##_a; \
        } \
    } \
    table tb_lookup_## R ##_## C ##_t2r {           \
        key = {  \
            hdr.aes.s## R ## C : exact;  \
            hdr.aes_meta.curr_round: exact;       \
        } \
        size = 3600; \
        actions = {  \
            write_v_## R ##_## C ##_a; \
        } \
    } \
    //done. note we actually need 256*14 entries at most
    
    #define GEN_LOOKUPS_FOR_R(R) \
    GEN_LOOKUP_TABLE(R,0) \
    GEN_LOOKUP_TABLE(R,1) \
    GEN_LOOKUP_TABLE(R,2) \
    GEN_LOOKUP_TABLE(R,3) \
    //for 4 cols at a time

    GEN_LOOKUPS_FOR_R(0)
    GEN_LOOKUPS_FOR_R(1)
    GEN_LOOKUPS_FOR_R(2)
    GEN_LOOKUPS_FOR_R(3)
    //all 16 tables generated.
    
    // Xor-ing 4 values (from 4 lookup tables) into 1 value.
    // Two-step process, first XOR two pairs, then XOR _a and _b
    
    #define GEN_XOR_INI_FOR_R(R,V1,V2,V3,V4) \
    action xor_s_## R ##_ini(){              \
        meta.ig_md.aes_tmp.s## R ##a= meta.ig_md.aes_tmp.v## V1 ^ \
                                 meta.ig_md.aes_tmp.v## V2;  \
        meta.ig_md.aes_tmp.s## R ##b= meta.ig_md.aes_tmp.v## V3 ^ \
                                 meta.ig_md.aes_tmp.v## V4;  \
    } \
    // First 2 XORs, also achieve shift-row
    GEN_XOR_INI_FOR_R(0, 00,11,22,33)
    GEN_XOR_INI_FOR_R(1, 10,21,32,03)
    GEN_XOR_INI_FOR_R(2, 20,31,02,13)
    GEN_XOR_INI_FOR_R(3, 30,01,12,23)


    #define GEN_XOR_FIN_FOR_R(R)   \
    action xor_s_## R ##_fin(){ \
        hdr.aes.s## R ## 0 = meta.ig_md.aes_tmp.s## R ##a [31:24] ^ meta.ig_md.aes_tmp.s## R ##b [31:24]; \
        hdr.aes.s## R ## 1 = meta.ig_md.aes_tmp.s## R ##a [23:16] ^ meta.ig_md.aes_tmp.s## R ##b [23:16]; \
        hdr.aes.s## R ## 2 = meta.ig_md.aes_tmp.s## R ##a [15: 8] ^ meta.ig_md.aes_tmp.s## R ##b [15: 8]; \
        hdr.aes.s## R ## 3 = meta.ig_md.aes_tmp.s## R ##a [ 7: 0] ^ meta.ig_md.aes_tmp.s## R ##b [ 7: 0]; \
    }  \
    // Last XOR, got 4 bytes instead of 1 32-bit
    GEN_XOR_FIN_FOR_R(0)
    GEN_XOR_FIN_FOR_R(1)
    GEN_XOR_FIN_FOR_R(2)
    GEN_XOR_FIN_FOR_R(3)
    
    action incr_and_recirc(bit<8> next_round){
        hdr.aes_meta.curr_round=next_round;
        
            //route to recirc port
            do_recirculate();
            
            //hdr.aes_meta.setValid();
            hdr.copy.setInvalid();
            
            hdr.udp.dst_port=AES_PORT+1;
    }
    action do_not_recirc(){
            route_to((bit<9>)hdr.aes_meta.dest_port);
            hdr.udp.dst_port=AES_PORT;
            
            hdr.aes_meta.setInvalid();
            hdr.copy.setValid();
            hdr.copy.copy=COPYRIGHT_STRING;
            
            hdr.udp.udp_total_len=(8+16+8);
            hdr.ipv4.total_len=(8+16+8)+20;
    }
    action do_not_recirc_final_xor(
        bit<8> s00,
        bit<8> s01,
        bit<8> s02,
        bit<8> s03,
        bit<8> s10,
        bit<8> s11,
        bit<8> s12,
        bit<8> s13,
        bit<8> s20,
        bit<8> s21,
        bit<8> s22,
        bit<8> s23,
        bit<8> s30,
        bit<8> s31,
        bit<8> s32,
        bit<8> s33
    ){
        do_not_recirc();
        
        hdr.aes.s00=hdr.aes.s00 ^ s00;
        hdr.aes.s01=hdr.aes.s01 ^ s01;
        hdr.aes.s02=hdr.aes.s02 ^ s02;
        hdr.aes.s03=hdr.aes.s03 ^ s03;
        hdr.aes.s10=hdr.aes.s10 ^ s10;
        hdr.aes.s11=hdr.aes.s11 ^ s11;
        hdr.aes.s12=hdr.aes.s12 ^ s12;
        hdr.aes.s13=hdr.aes.s13 ^ s13;
        hdr.aes.s20=hdr.aes.s20 ^ s20;
        hdr.aes.s21=hdr.aes.s21 ^ s21;
        hdr.aes.s22=hdr.aes.s22 ^ s22;
        hdr.aes.s23=hdr.aes.s23 ^ s23;
        hdr.aes.s30=hdr.aes.s30 ^ s30;
        hdr.aes.s31=hdr.aes.s31 ^ s31;
        hdr.aes.s32=hdr.aes.s32 ^ s32;
        hdr.aes.s33=hdr.aes.s33 ^ s33;
    }
    
    table tb_recirc_decision {
        key = {
            hdr.aes_meta.curr_round : exact;
        }
        actions = {
            incr_and_recirc;
            do_not_recirc;
            do_not_recirc_final_xor;
        }
        size = 20;
        default_action = do_not_recirc;
    }

    // From the assignment 3 (action + table)
    action forward(egressSpec_t port) {
        //standard_metadata.egress_spec = port;
	send_to_port(ostd, port);
    }

    action flood() {
        //standard_metadata.mcast_grp = MCAST_ID;
	multicast(ostd,MCAST_ID);
    }
    // Table from the assignment3
    table switch_table {
        key = {
            hdr.ethernet.dstAddr: exact;
            meta.vid: exact;
            //hdr.vlan.vid: exact;
        }
        actions = {
            flood;
            forward;
        }
        size = 1024;
        default_action = flood;
    }
    
    apply {
        bool is_aes=hdr.aes.isValid();
        if(!is_aes){
            drop();
            exit;
        }
        
        if(! hdr.aes_meta.isValid()){
            //init!
            hdr.aes_meta.setValid();
            hdr.aes_meta.curr_round=0;
            hdr.aes_meta.ff=0xff;
            
            //packet routing: skip routing now, we simply bounce back the packet. 
            //any routing match-action logic should be added here.
            //hdr.aes_meta.dest_port= (bit<16>)(ig_intr_md.ingress_port);
            hdr.aes_meta.dest_port= (bit<16>)(istd.ingress_port);
            
            //erase udp checksum
            hdr.udp.checksum=0;
        }
        
        //Tofino 32-port has 2x 100G recirc ports. Use any one of them.
        get_rnd_bit();//ig_md.rnd_bit;
        if(meta.ig_md.rnd_bit==0){
            meta.ig_md.rnd_port_for_recirc=68;
        }else{
            meta.ig_md.rnd_port_for_recirc=68+128;
        }
        
        
        
        //1st encryption round
        
        tb_lookup_0_0_t.apply();
        tb_lookup_0_1_t.apply();
        tb_lookup_0_2_t.apply();
        tb_lookup_0_3_t.apply();
        tb_lookup_1_0_t.apply();
        tb_lookup_1_1_t.apply();
        tb_lookup_1_2_t.apply();
        tb_lookup_1_3_t.apply();
        tb_lookup_2_0_t.apply();
        tb_lookup_2_1_t.apply();
        tb_lookup_2_2_t.apply();
        tb_lookup_2_3_t.apply();
        tb_lookup_3_0_t.apply();
        tb_lookup_3_1_t.apply();
        tb_lookup_3_2_t.apply();
        tb_lookup_3_3_t.apply();
        
        xor_s_0_ini();
        xor_s_0_fin();
        xor_s_1_ini();
        xor_s_1_fin();
        xor_s_2_ini();
        xor_s_2_fin();
        xor_s_3_ini();
        xor_s_3_fin();
        
        //2nd encryption round
        
        tb_lookup_0_0_t2r.apply();
        tb_lookup_0_1_t2r.apply();
        tb_lookup_0_2_t2r.apply();
        tb_lookup_0_3_t2r.apply();
        tb_lookup_1_0_t2r.apply();
        tb_lookup_1_1_t2r.apply();
        tb_lookup_1_2_t2r.apply();
        tb_lookup_1_3_t2r.apply();
        tb_lookup_2_0_t2r.apply();
        tb_lookup_2_1_t2r.apply();
        tb_lookup_2_2_t2r.apply();
        tb_lookup_2_3_t2r.apply();
        tb_lookup_3_0_t2r.apply();
        tb_lookup_3_1_t2r.apply();
        tb_lookup_3_2_t2r.apply();
        tb_lookup_3_3_t2r.apply();
        
        xor_s_0_ini();
        xor_s_0_fin();
        xor_s_1_ini();
        xor_s_1_fin();
        xor_s_2_ini();
        xor_s_2_fin();
        xor_s_3_ini();
        xor_s_3_fin();
        
        
        tb_recirc_decision.apply();

	meta.ingress_port = istd.ingress_port;

	// From the assignment 3
        if (hdr.ethernet.etherType == ETH_TYPE_VLAN) { // VLAN-enabled
            if (meta.etherType == ETH_TYPE_ARP) { // VLAN-enabled + ARP packet
                flood();
            }
            else { // VLAN-enabled + Non-ARP packet
                switch_table.apply();
            }
        }
        else if (hdr.ethernet.etherType == ETH_TYPE_ARP) { // Non-VLAN + ARP packet
            flood();
        }
        else { // Non-VLAN + Non-ARP packet
            switch_table.apply();
        }
    }
}

/****************************************************************************************/
/**************************  (AES) Ingress Deparser  ************************************/
/****************************************************************************************/

//control IngressDeparserImpl(packet_out buffer,
//                            out empty_metadata_t clone_i2e_meta,
//                            out empty_metadata_t resubmit_meta,
//                            out empty_metadata_t normal_meta,
//                            inout headers_t hdr,
//                            in metadata_t meta,
//                            in psa_ingress_output_metadata_t istd)

control SwitchIngressDeparser(
    packet_out packet, 
    out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta,
    out empty_metadata_t normal_meta,
    inout headers hdr,
    in metadata meta,
    in psa_ingress_output_metadata_t istd) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.aes);
        packet.emit(hdr.aes_meta);
        packet.emit(hdr.copy);

	// From the assignment3
        packet.emit(hdr.vlan);
        packet.emit(hdr.packet_in);
    }
}

/*********************************************************************************/
/***************************  Egress Parser  *************************************/
/*********************************************************************************/
//parser EgressParserImpl(packet_in buffer,
//                        out headers_t parsed_hdr,
//                        inout metadata_t user_meta,
//                        in psa_egress_parser_input_metadata_t istd,
//                        in empty_metadata_t normal_meta,
//                        in empty_metadata_t clone_i2e_meta,
//                        in empty_metadata_t clone_e2e_meta)

parser SwitchEgressParser(
        packet_in pkt,
        out headers hdr,
        inout metadata meta,
        in psa_egress_parser_input_metadata_t istd,
        in empty_metadata_t normal_meta,
        in empty_metadata_t clone_i2e_meta,
        in empty_metadata_t clone_e2e_meta) {
    state start {
        //pkt.extract(eg_intr_md);
        transition accept;
    }
}

/********************************************************************************/
/************************  (AES) Egress Processing  *****************************/
/********************************************************************************/

//control egress(inout headers_t hdr,
//               inout metadata_t user_meta,
//               in    psa_egress_input_metadata_t  istd,
//               inout psa_egress_output_metadata_t ostd)

control SwitchEgress(
	inout headers hdr,
        inout metadata meta,
        in    psa_egress_input_metadata_t  istd,
        inout psa_egress_output_metadata_t ostd) {

    action noop() {
        /* empty */
    }
    
    action drop() {
        //mark_to_drop(standard_metadata);
	egress_drop(ostd);
    }

    action to_controller() {
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = meta.ingress_port;
    }

    // From the assignment 3
    table vlan_table {
        key = {
	    //hdr.vlan.vid: exact;
	    meta.vid: exact;
            //standard_metadata.egress_port: exact;
	    istd.egress_port: exact;
        }
        actions = {
            noop;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    // From the assignment 3
    apply {
        // (1) Prune multicast packets going to ingress port to prevent loops
        //if (standard_metadata.egress_port == meta.ingress_port)
        if (istd.egress_port == meta.ingress_port)
            drop();


        // (2) Send a copy of the packet to the controller for learning
        if (istd.egress_port == CPU_PORT)
            to_controller();

	// (3) Check if the VLAN header exists. If yes, then drop packets ...
	if (hdr.ethernet.etherType == ETH_TYPE_VLAN) {
	    vlan_table.apply();
	}
    }
}

/*********************************************************************************/
/***************************  Egress Deparser  *************************************/
/*********************************************************************************/

//control EgressDeparserImpl(packet_out buffer,
//                           out empty_metadata_t clone_e2e_meta,
//                           out empty_metadata_t recirculate_meta,
//                           inout headers_t hdr,
//                           in metadata_t meta,
//                           in psa_egress_output_metadata_t istd,
//                           in psa_egress_deparser_input_metadata_t edstd)

control SwitchEgressDeparser(
        packet_out pkt,
        out empty_metadata_t clone_e2e_meta,
        out empty_metadata_t recirculate_meta,
        inout headers hdr,
        in metadata meta,
        in psa_egress_output_metadata_t istd,
        in psa_egress_deparser_input_metadata_t edstd) {
    apply {
    }
}

/**************************************************************************/
/*********************  Checksum Verification  *****************************/
/**************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/**************************************************************************/
/*********************  Checksum Computation  *****************************/
/**************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/**************************************************************************/
/***************************  Switch  *************************************/
/**************************************************************************/

// original assignment3
// V1Switch(
// MyParser(),
// MyVerifyChecksum(),
// MyIngress(),
// MyEgress(),
// MyComputeChecksum(),
// MyDeparser()
// ) main;

// Original AES
//Pipeline (SwitchIngressParser(),
//         SwitchAESIngress(),
//	 SwitchTableIngress(),
//         SwitchIngressDeparser(),
//         SwitchEgressParser(),
//         SwitchEgress(),
//         SwitchEgressDeparser()
//         ) pipe;

IngressPipeline(SwitchIngressParser(),
SwitchIngress(),
SwitchIngressDeparser()) ip;

EgressPipeline(SwitchEgressParser(),
SwitchEgress(),
SwitchEgressDeparser()) ep;

PSA_Switch(ip,PacketReplicationEngine(),ep,BufferingQueueingEngine()) main;
