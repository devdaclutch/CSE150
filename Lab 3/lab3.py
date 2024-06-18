from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
log = core.getLogger()
class Firewall(object):
def __init__(self, connection):
self.connection = connection
connection.addListeners(self)
log.debug("Firewall instance created for %s", connection)
def do_firewall(self, packet, packet_in):
# Variables
idle_timeout = 30 # Time taken to timeout in seconds
hard_timeout = 60 # Max time taken to timeout in seconds
# Create a flow modification message
msg = of.ofp_flow_mod()
msg.match = of.ofp_match.from_packet(packet)
msg.idle_timeout = idle_timeout
msg.hard_timeout = hard_timeout
msg.buffer_id = packet_in.buffer_id
protocol_TCP = packet.find('tcp')
protocol_ARP = packet.find('arp')
# Check Protocol and install rules accordingly
if protocol_TCP is not None:
# Allow TCP traffic
action = of.ofp_action_output(port=of.OFPP_FLOOD)
msg.actions.append(action)
log.debug("Installing TCP flow for %s -> %s", packet.src, packet.dst)
elif protocol_ARP is not None:
# Allow ARP traffic
action = of.ofp_action_output(port=of.OFPP_FLOOD)
msg.actions.append(action)
log.debug("Installing ARP flow for %s -> %s", packet.src, packet.dst)
else:
# Drop all other traffic
log.debug("Dropping non-TCP/ARP packet from %s -> %s", packet.src,
packet.dst)
# Send the message to the switch
log.debug("Sending flow mod message: %s", msg)
self.connection.send(msg)
def _handle_PacketIn(self, event):
packet = event.parsed
packet_in = event.ofp
log.debug("PacketIn: %s -> %s", packet.src, packet.dst)
self.do_firewall(packet, packet_in)
def launch():
def start_switch(event):
log.debug("Controlling %s", event.connection)
Firewall(event.connection)
core.openflow.addListenerByName("ConnectionUp", start_switch)