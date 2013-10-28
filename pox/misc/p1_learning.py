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
      if message is not None: log.debug(message)
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
    
    def drop ():
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      # this msg has no actions, so the pack wil be dropped
      self.connection.send(msg)

    # updating out mac to port mapping
    self.mac_to_port[packet.src] = event.port

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      log.debug("Dropping a packet of type %s" % (packet.type,))
      drop()
      return
    log.debug ("got a packet");
    if (packet.type == packet.ARP_TYPE):
      log.debug("got an arp packet")
      pass

    if packet.dst not in self.mac_to_port:
      flood("Port for %s unknown -- flooding" % (packet.dst,))
    else:
      # install a rule in the switch and send packet to its destination
      toInstallPort = self.mac_to_port[packet.dst]
      msg = of.ofp_flow_mod()
      #msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.match = of.ofp_match(dl_dst = packet.dst)
      msg.actions.append(of.ofp_action_output(port = toInstallPort))
      msg.data = event.ofp
      log.debug("installing flow for %s.%i -> %s.%i" %
        (packet.src, event.port, packet.dst, toInstallPort))
      self.connection.send(msg)

class p1_learning (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(p1_learning)
