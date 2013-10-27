"""
Author Tariq Rafique
based on work by Junaid Khalid (CSEP561 site)

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from POX l2_learning.py only for IPv4.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.mac_to_port = {}
    self.listenTo(connection)
    

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()

    def flood (message = None):
      msg = of.ofp_packet_out();
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD));
      # where does event data go ? 
      msg.data = event.ofp;
      msg.in_port = event.port;
      self.connection.send(msg);
    
    # updating out mac to port mapping
    self.mac_to_port[packet.src] = event.port;

    if packet.dst not in self.mac_to_port:
      log.debug("Port for %s unknown -- flooding" % (packet.dst,))
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)      

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

class learning_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(learning_switch)
