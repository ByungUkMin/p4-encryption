############################################################################
##
##     This file is part of Purdue CS 536.
##
##     Purdue CS 536 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     Purdue CS 536 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with Purdue CS 536. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

import json
import argparse
import contextlib
import p4runtime_sh.shell as p4sh
from p4.v1 import p4runtime_pb2 as p4rt

###############################################################################
# Default parameters
###############################################################################

# Relative path of the configuration, logs, and topo directories
CFG_DIR = 'cfg'
LOGS_DIR = 'logs'

# Bridge ID and number of ports
BRIDGE_ID = 1
BRIDGE_CPU_PORT = 255

# Logs threshold
NUM_LOGS_THRESHOLD = 10

# Ethernet type values (https://en.wikipedia.org/wiki/EtherType)
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100


###############################################################################
# Helper functions
###############################################################################

# MAC address in bytes to string
def mac2str(mac):
    return ':'.join('{:02x}'.format(b) for b in mac)


###############################################################################
# Multicast group functions
###############################################################################

# Create a multicast group entry
def InstallMcastGrpEntry(mcast_group_id, bridge_ports):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    for port in bridge_ports:
        mcast_entry.add(port)
    mcast_entry.insert()

# Delete a multicast group entry
def DeleteMcastGrpEntry(mcast_group_id):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    mcast_entry.delete()


###############################################################################
# Packet processing functions
###############################################################################

# Process incoming packets
def ProcPacketIn(switch_name, logs_dir, num_logs_threshold):
    try:
        num_logs = 0
        while True:
            rep = p4sh.client.get_stream_packet("packet", timeout=1)
            if rep is not None:
                # Read the raw packet
                payload = rep.packet.payload
                
                 # Parse Metadata
                ingress_port_in_bytes = rep.packet.metadata[0].value
                ingress_port = int.from_bytes(ingress_port_in_bytes, "big")

                # Parse Ethernet header
                dst_mac_in_bytes = payload[0:6]
                dst_mac = mac2str(dst_mac_in_bytes)
                src_mac_in_bytes = payload[6:12]
                src_mac = mac2str(src_mac_in_bytes)
                eth_type_in_bytes = payload[12:14]
                eth_type = int.from_bytes(eth_type_in_bytes, "big")

                if eth_type == ETH_TYPE_VLAN:
                    # Parse VLAN header
                    vlan_id_in_bytes = payload[14:16]
                    vlan_id = int.from_bytes(vlan_id_in_bytes, "big")

                    print("PacketIn: dst={0} src={1} vlan={2} port={3}".format(
                        dst_mac, src_mac, vlan_id, ingress_port))
                else:
                    print("PacketIn: dst={0} src={1} port={2}".format(
                        dst_mac, src_mac, ingress_port))

                try:
                    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
                        # within the table_entry.match get/set objects

                        ##################################################################################
                        # Learning Switch Logic - Begins #################################################
                        ##################################################################################

                        # TODO: For each incoming ARP packet, learn the mapping between the tuple (source 
                        # Ethernet address, VLAN ID) to ingress port. For non-VLAN packets, set the VLAN 
                        # ID to 0. 
                        # Install flow entries in switch table (you specified in the P4 program):
                        #   - Match fields: Ethernet address, VLAN ID
                        #   - Action: `SwitchTableIngress.forward`` | parameter: `port``
                        #
                        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
                        # table entries.

                        if eth_type == ETH_TYPE_VLAN:
                            isARPCheck_in_bytes = payload[16:18]
                            isARPCheck = int.from_bytes(isARPCheck_in_bytes, "big")
                            if isARPCheck == ETH_TYPE_ARP: # VLAN-enabled + ARP packet
                                table_entry = p4sh.TableEntry('SwitchAESIngress.switch_table')(action='SwitchAESIngress.forward')
                                table_entry.match['hdr.ethernet.dstAddr'] = src_mac
                                table_entry.match['meta.vid'] = str(vlan_id)
                                table_entry.action['port'] = str(ingress_port)
                                table_entry.insert()

                        #elif eth_type == ETH_TYPE_ARP:  # Non-VLAN + ARP packet
                        else:  # Non-VLAN + ARP packet
                            table_entry = p4sh.TableEntry('SwitchAESIngress.switch_table')(action='SwitchAESIngress.forward')
                            table_entry.match['hdr.ethernet.dstAddr'] = src_mac
                            table_entry.match['meta.vid'] = str(0)
                            table_entry.action['port'] = str(ingress_port)
                            table_entry.insert()

                        ##################################################################################
                        # Learning Switch Logic - Ends ###################################################
                        ##################################################################################

                except:
                    pass

            # Log the Ethernet address to port mapping
            num_logs += 1
            if num_logs == num_logs_threshold:
                num_logs = 0
                with open('{0}/{1}-table.json'.format(logs_dir, switch_name), 'w') as outfile:
                    with contextlib.redirect_stdout(outfile):
                        p4sh.TableEntry('SwitchAESIngress.switch_table').read(lambda te: print(te))
                print(
                    "INFO: Log committed to {0}/{1}-table.json".format(logs_dir, switch_name))
    except KeyboardInterrupt:
        return None
###############################################################################
# Encryption 
###############################################################################

#def table_add(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list):
#    # simply a wrapper
#    t=bfrt_info.table_dict[table_name]
#    
#    def table_add_gen_kd(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list):
#        # prepare to add a single match-action table rule
#        t=bfrt_info.table_dict[table_name]
#
#        # prepare KeyTuple
#        KeyTuple_list=[]
#        for keyName, keyValue in zip(match_key_names_list,match_key_values_list):
#            KeyTuple_list.append(client.KeyTuple(name=keyName, value=keyValue))
#        tKey=t.make_key(KeyTuple_list)
#
#        DataTuple_List=[]
#        for dataName, dataValue in zip(action_data_names_list,action_data_values_list):
#            DataTuple_List.append(client.DataTuple(name=dataName,val=dataValue))
#        tData=t.make_data(DataTuple_List, action_name=action_name)
#        return tKey, tData
#    
#    tKey,tData=table_add_gen_kd(table_name, match_key_names_list, match_key_values_list, action_name, action_data_names_list, action_data_values_list)
#    
#    return t.entry_add(target=client.Target(), key_list=[tKey], data_list=[tData])

def add_everything(mykey):
    key=parse_key(mykey)
    expanded_key=expand_key(key)
    LUTs,FinalXORvect=generate_LUT(expanded_key)

    #import controller_stub
    #table_add=controller_stub.table_add

    #sys.stderr.write("#** Using key = %s \n"%(hex(key)))
    #sys.stderr.write("#** Installing recirculation rules... \n")
    #recirc table
    
    for rndNum in range(1,10-1,2):
        curr_round=rndNum-1
        #table_add(table_name='SwitchAESIngress.tb_recirc_decision', match_key_names_list=['hdr.aes_meta.curr_round'], match_key_values_list=[curr_round], action_name='incr_and_recirc', action_data_names_list=['next_round'], action_data_values_list=[curr_round+2])
        table_entry = p4sh.TableEntry('SwitchAESIngress.tb_recirc_decision')(action='SwitchAESIngress.incr_and_recirc')
        table_entry.match['hdr.aes_meta.curr_round'] = curr_round
        table_entry.action['next_round'] = str(curr_round + 2)
        table_entry.insert()

    last_round=8
    fields_list=['s%d%d' %(i,j) for i in range(4) for j in range(4)]
    values_list=[FinalXORvect[i][j] for i in range(4) for j in range(4)]

    #table_add(table_name='SwitchAESIngress.tb_recirc_decision', match_key_names_list=['hdr.aes_meta.curr_round'], match_key_values_list=[last_round], action_name='do_not_recirc_final_xor',     action_data_names_list=fields_list, action_data_values_list=values_list)

    for fields, values in zip(fields_list, values_list):
        table_entry = p4sh.TableEntry('SwitchAESIngress.tb_recirc_decision')(action='SwitchAESIngress.do_not_recirc_final_xor')
        table_entry.match['hdr.aes_meta.curr_round'] = last_round
        table_entry.action[fields] = str(values)
        table_entry.insert()

    print("#** Installing lookup table rules... \n")

    for rndNum in range(1,10+1,2):
        curr_round=rndNum-1   
        
        luts1=LUTs[rndNum]
        luts2=LUTs[rndNum+1]
        
        def printRules1(lutR,lutC,  inputR, inputC):
            r,c=inputR, inputC
            tname="SwitchAESIngress.tb_lookup_%d_%d_t"%(r,c)
            aname="write_v_%d_%d_a"%(r,c)
            kname="hdr.aes.s%d%d"%(r,c)

            LUT=luts1[lutR][lutC]
            for s_match,v_val in LUT.dump():
                #table_add(table_name=tname, match_key_names_list=[kname,'hdr.aes_meta.curr_round'], match_key_values_list=[s_match,curr_round], action_name=aname, action_data_names_list=['v'], action_data_values_list=[v_val])
                table_entry = p4sh.TableEntry(str(tname))(action=str(aname))
                table_entry.match['hdr.aes_meta.curr_round'] = curr_round
                table_entry.match[str(kname)] = str(s_match)
                table_entry.action['v'] = str(v_val)
                table_entry.insert()
                
        def printRules2(lutR,lutC,  inputR, inputC):
            r,c=inputR, inputC
            tname="SwitchAESIngress.tb_lookup_%d_%d_t2r"%(r,c)
            aname="write_v_%d_%d_a"%(r,c)
            kname="hdr.aes.s%d%d"%(r,c)

            LUT=luts2[lutR][lutC]
            for s_match,v_val in LUT.dump():
                #table_add(table_name=tname, match_key_names_list=[kname,'hdr.aes_meta.curr_round'], match_key_values_list=[s_match,curr_round], action_name=aname, action_data_names_list=['v'], action_data_values_list=[v_val])
                table_entry = p4sh.TableEntry(str(tname))(action=str(aname))
                table_entry.match['hdr.aes_meta.curr_round'] = curr_round
                table_entry.match[str(kname)] = str(s_match)
                table_entry.action['v'] = str(v_val)
                table_entry.insert()

        #nvect0
        printRules1(0,0  ,  0,0)
        printRules1(0,1  ,  1,1)
        printRules1(0,2  ,  2,2)
        printRules1(0,3  ,  3,3)
        #nvect1
        printRules1(1,0  ,  1,0)
        printRules1(1,1  ,  2,1)
        printRules1(1,2  ,  3,2)
        printRules1(1,3  ,  0,3)
        #nvect2
        printRules1(2,0  ,  2,0)
        printRules1(2,1  ,  3,1)
        printRules1(2,2  ,  0,2)
        printRules1(2,3  ,  1,3)
        #nvect3
        printRules1(3,0  ,  3,0)
        printRules1(3,1  ,  0,1)
        printRules1(3,2  ,  1,2)
        printRules1(3,3  ,  2,3)

        #nvect0
        printRules2(0,0  ,  0,0)
        printRules2(0,1  ,  1,1)
        printRules2(0,2  ,  2,2)
        printRules2(0,3  ,  3,3)
        #nvect1
        printRules2(1,0  ,  1,0)
        printRules2(1,1  ,  2,1)
        printRules2(1,2  ,  3,2)
        printRules2(1,3  ,  0,3)
        #nvect2
        printRules2(2,0  ,  2,0)
        printRules2(2,1  ,  3,1)
        printRules2(2,2  ,  0,2)
        printRules2(2,3  ,  1,3)
        #nvect3
        printRules2(3,0  ,  3,0)
        printRules2(3,1  ,  0,1)
        printRules2(3,2  ,  1,2)
        printRules2(3,3  ,  2,3)

    sys.stderr.write("#** Done! \n")


def add_encryption(mykey):
    try:
        add_everything(mykey)
    except:
        raise
    finally:
        controller_stub.close()

###############################################################################
# Main 
###############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Switch Script')
    parser.add_argument('--grpc-port', help='GRPC Port', required=True,
                        type=str, action="store", default='50001')
    parser.add_argument('--topo-config', help='Topology Configuration File', required=True,
                        type=str, action="store")
    parser.add_argument('--encrypted', help='AES encryption key', required=True,
                        type=int, action="store")
    args = parser.parse_args()

    # Create a bridge name postfixed with the grpc port number
    if args.encrypted == 1: # wo AES
        switch_name = 'switch-woAES-{0}'.format(args.grpc_port)
    elif args.encrypted == 2: # AES
        switch_name = 'switch-AES-{0}'.format(args.grpc_port)

    # Get Multicast/VLAN ID to ports mapping
    with open(args.topo_config, 'r') as infile:
        topo_config = json.loads(infile.read())

    mcast_group_id = topo_config['switch'][args.grpc_port]['mcast']['id']
    mcast_group_ports = topo_config['switch'][args.grpc_port]['mcast']['ports']

    vlan_id_to_ports_map = {}
    for vlan_id, ports in topo_config['switch'][args.grpc_port]['vlan_id_to_ports'].items():
        vlan_id_to_ports_map[int(vlan_id)] = ports

    # Setup the P4Runtime connection with the bridge
    p4sh.setup(
        device_id=BRIDGE_ID, grpc_addr='127.0.0.1:{0}'.format(args.grpc_port), election_id=(0, 1),
        config=p4sh.FwdPipeConfig(
            '{0}/{1}-p4info.txt'.format(CFG_DIR, switch_name),  # Path to P4Info file
            '{0}/{1}.json'.format(CFG_DIR, switch_name)  # Path to config file
        )
    )

    print("Switch Started @ Port: {0}".format(args.grpc_port))
    print("Press CTRL+C to stop ...")

    # Install broadcast rule
    InstallMcastGrpEntry(mcast_group_id, mcast_group_ports + [BRIDGE_CPU_PORT])

    # Install VLAN rules
    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
        # within the table_entry.match get/set objects

        ##################################################################################
        # Install VLAN Rules - Begins ####################################################
        ##################################################################################

        # TODO: Install flow entries to let packets traverse only those egress ports that 
        # match its VLAN ID.
        # Install flow entries in the VLAN table (as specified in the P4 program):
        #   - Match fields: `standard_metadata.egress_port`, VLAN ID
        #   - Action: `MyEgress.noop`
        #
        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
        # table entries.
        if vlan_id_to_ports_map:
            for vlan_id in vlan_id_to_ports_map:
                for port in vlan_id_to_ports_map[vlan_id]:
                    table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='MyEgress.noop')
                    table_entry.match['standard_metadata.egress_port'] = str(port)
                    table_entry.match['meta.vid'] = str(vlan_id)
                    table_entry.insert()
        else:
            for port in mcast_group_ports:
                table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='MyEgress.noop')
                table_entry.match['standard_metadata.egress_port'] = str(port)
                table_entry.match['meta.vid'] = str(0)
                table_entry.insert()

        ##################################################################################
        # Install VLAN Rules - Ends ######################################################
        ##################################################################################

    with open('{0}/{1}-vlan-table.json'.format(LOGS_DIR, switch_name), 'w') as outfile:
        with contextlib.redirect_stdout(outfile):
            p4sh.TableEntry('MyEgress.vlan_table').read(lambda te: print(te))
        print("INFO: Log committed to {0}/{1}-vlan-table.json".format(LOGS_DIR, switch_name))

        ##################################################################################
        # Encryption starts  ######################################################
        ##################################################################################
    #if args.enc_key == None:
    #    sys.stderr.write("Install AES-128 key into Scrambled Lookup Tables in the P4 data plane program.")
    #    sys.stderr.write("Example: python switch-AES.py --topo-config=topo/$(topo).json --grpc-port=50001 --enc-key 0x10002000300040005000600070008000 \n")
    #    sys.exit(-1)

    #add_encryption(args.enc_key)

        ##################################################################################
        # Encryption ends  ######################################################
        ##################################################################################
    # Start the packet-processing loop
    ProcPacketIn(switch_name, LOGS_DIR, NUM_LOGS_THRESHOLD)

    print("Switch Stopped")

    # Delete broadcast rule
    DeleteMcastGrpEntry(mcast_group_id)

    # Delete VLAN rules
    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
        # within the table_entry.match get/set objects

        ##################################################################################
        # Delete VLAN Rules - Begins #####################################################
        ##################################################################################

        # TODO: Delete VLAN flow entries.
        # Delete flow entries from the VLAN table (as specified in the P4 program):
        #   - Match fields: `standard_metadata.egress_port`, VLAN ID
        #   - Action: `MyEgress.noop`
        #
        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
        # table entries.

        for vlan_id in vlan_id_to_ports_map:
            table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='MyEgress.noop')
            for port in vlan_id_to_ports_map[vlan_id]:
                table_entry.match['standard_metadata.egress_port'] = str(port)
                table_entry.match['meta.vid'] = str(vlan_id)
                table_entry.delete()

        ##################################################################################
        # Delete VLAN Rules - Ends #######################################################
        ##################################################################################




    # Close the P4Runtime connection
    p4sh.teardown()
