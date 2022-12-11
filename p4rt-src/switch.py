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
                    vlan_id = int(int.from_bytes(payload[14:16], "big") & 0x0FFF)

                    print("PacketIn: dst={0} src={1} vlan={2} port={3} eth_type = {3}".format(dst_mac, src_mac, vlan_id, ingress_port, eth_type))
                else:
                    print("PacketIn: dst={0} src={1} port={2} eth_type = {3}".format(dst_mac, src_mac, ingress_port, eth_type))

                try:
                    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
                        # within the table_entry.match get/set objects

                        if eth_type == ETH_TYPE_VLAN:
                            isARPCheck_in_bytes = payload[16:18]
                            isARPCheck = int.from_bytes(isARPCheck_in_bytes, "big")
                            if isARPCheck == ETH_TYPE_ARP: # VLAN-enabled + ARP packet
                                table_entry = p4sh.TableEntry('MyIngress.switch_table')(action='MyIngress.forward')
                                table_entry.match['hdr.ethernet.dstAddr'] = src_mac
                                table_entry.match['meta.vid'] = str(vlan_id)
                                table_entry.action['port'] = str(ingress_port)
                                table_entry.insert()

                        #else:  # Non-VLAN + ARP packet
                        elif eth_type == ETH_TYPE_ARP:  # Non-VLAN + ARP packet
                            table_entry = p4sh.TableEntry('MyIngress.switch_table')(action='MyIngress.forward')
                            table_entry.match['hdr.ethernet.dstAddr'] = src_mac
                            table_entry.match['meta.vid'] = str(0)
                            table_entry.action['port'] = str(ingress_port)
                            table_entry.insert()
                except:
                    pass

    except KeyboardInterrupt:
        return None

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
    ProcPacketIn(switch_name, LOGS_DIR, NUM_LOGS_THRESHOLD)

    print("Switch Stopped")

    # Delete broadcast rule
    DeleteMcastGrpEntry(mcast_group_id)

    # Delete VLAN rules
    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
        for vlan_id in vlan_id_to_ports_map:
            table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='MyEgress.noop')
            for port in vlan_id_to_ports_map[vlan_id]:
                table_entry.match['standard_metadata.egress_port'] = str(port)
                table_entry.match['meta.vid'] = str(vlan_id)
                table_entry.delete()

    # Close the P4Runtime connection
    p4sh.teardown()
