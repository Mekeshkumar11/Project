from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3   # ✅ use OpenFlow 1.3
import csv
import time

class FeatureCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]   # ✅ fixed

    def __init__(self, *args, **kwargs):
        super(FeatureCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # CSV file setup
        self.csv_file = open("network_features.csv", "w", newline="")
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow([
            "timestamp", "dpid", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packet_count", "byte_count", "duration_sec",
            "packet_rate", "byte_rate"
        ])

    # Register datapaths (switches)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # Monitor periodically
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)   # request every 5 sec

    def _request_stats(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Handle flow stats reply
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = int(time.time())
        body = ev.msg.body

        for stat in body:
            if 'ipv4_src' in stat.match and 'ipv4_dst' in stat.match:
                src_ip = stat.match['ipv4_src']
                dst_ip = stat.match['ipv4_dst']
                src_port = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                dst_port = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                protocol = stat.match.get('ip_proto', 0)

                packet_count = stat.packet_count
                byte_count = stat.byte_count
                duration = stat.duration_sec + stat.duration_nsec / 1e9

                # Derived features
                packet_rate = packet_count / duration if duration > 0 else 0
                byte_rate = byte_count / duration if duration > 0 else 0

                # Save to CSV
                self.csv_writer.writerow([
                    timestamp, ev.msg.datapath.id, src_ip, dst_ip,
                    src_port, dst_port, protocol,
                    packet_count, byte_count, duration,
                    packet_rate, byte_rate
                ])
                self.csv_file.flush()
