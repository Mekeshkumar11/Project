# feature_collector.py
#
# Ryu app that acts as a learning switch AND collects flow features into CSV
#
# Run with: ryu-manager feature_collector.py
# Start Mininet: 
#   sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
from ryu.lib import hub
import csv
import os
import time


class FeatureCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FeatureCollector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}          # For learning switch
        self.datapaths = {}            # Track connected switches
        self.monitor_thread = hub.spawn(self._monitor)

        # Prepare CSV file
        self.csv_file = "flow_features.csv"
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "datapath", "src_ip", "dst_ip", "src_port", "dst_port",
                    "protocol", "packet_count", "byte_count", "duration_sec"
                ])

    # Register switches
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    # Learning switch behavior
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a mac address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid future packet_in
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    # Periodically ask for flow stats
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Handle flow stats reply
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            if 'eth_type' in stat.match and stat.match['eth_type'] == ether_types.ETH_TYPE_IP:
                src_ip = stat.match.get('ipv4_src', "0.0.0.0")
                dst_ip = stat.match.get('ipv4_dst', "0.0.0.0")
                proto = stat.match.get('ip_proto', 0)
                src_port = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                dst_port = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        time.time(),
                        ev.msg.datapath.id,
                        src_ip, dst_ip, src_port, dst_port,
                        proto,
                        stat.packet_count,
                        stat.byte_count,
                        stat.duration_sec
                    ])
