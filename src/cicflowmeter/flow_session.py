import csv
from collections import defaultdict
import time
from threading import Thread, Lock

from scapy.sessions import DefaultSession

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow

import requests


EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
# GARBAGE_COLLECT_PACKETS = 100
SENDING_INTERVAL = 1

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        if self.output_mode == "flow":
            output = open(self.output_file, "w")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)
        self.GARBAGE_COLLECT_PACKETS = 10000 if not self.url_model else 100


        self.start_time = 0
        self.lock = Lock() 
        thread = Thread(target=self.send_flows_to_server)
        thread.start()

        super(FlowSession, self).__init__(*args, **kwargs)

    def send_flows_to_server(self):
        while True:
            if len(self.flows) != 0:
                flows = list(self.flows.values())
                data = {'flows': [flow.get_data() for flow in flows]}
                requests.post('http://127.0.0.1:5000/send_traffic', json=data)
                self.garbage_collect()
            time.sleep(SENDING_INTERVAL)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect()
        return super(FlowSession, self).toPacketList()
    

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD
        
        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            with self.lock:
                self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    with self.lock:
                        self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            # self.garbage_collect(packet.time)                    
            return

        flow.add_packet(packet, direction)

        current_time = time.time()
        if current_time - self.start_time >= SENDING_INTERVAL:
            self.start_time = current_time
            self.garbage_collect()

        # if not self.url_model:
        #     GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % self.GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect()

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self) -> None:
        with self.lock:
            self.flows = {}



def generate_session_class(output_mode, output_file, url_model):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
        },
    )
