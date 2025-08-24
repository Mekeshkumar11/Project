# feature_collector.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import csv
import time
import os

class FeatureCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FeatureCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # CSV setup
        self.csv_file = "flow_features.csv"
        self.csv_header = ["timestamp", "datapath", "src_ip", "dst_ip", 
                           "src_port", "dst_port", "protocol", 
                           "packet_count", "byte_count", "duration_sec"]

        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.csv_header)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Registering datapath: %s", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("Unregistering datapath: %s", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)  # request stats every 5 seconds

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            # Ignore table-miss flow (priority 0)
            if stat.priority == 0:
                continue

            match = stat.match
            timestamp = time.time()
            datapath = ev.msg.datapath.id

            src_ip = match.get("ipv4_src", "")
            dst_ip = match.get("ipv4_dst", "")
            src_port = match.get("tcp_src", match.get("udp_src", ""))
            dst_port = match.get("tcp_dst", match.get("udp_dst", ""))
            protocol = match.get("ip_proto", "")

            packet_count = stat.packet_count
            byte_count = stat.byte_count
            duration_sec = stat.duration_sec

            row = [timestamp, datapath, src_ip, dst_ip, 
                   src_port, dst_port, protocol, 
                   packet_count, byte_count, duration_sec]

            # Append to CSV
            with open(self.csv_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(row)

            self.logger.info("Flow stat: %s", row)
