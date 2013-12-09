"""
Author Tariq Rafique
based on work by Junaid Khalid (CSEP561 site)

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from POX l2_learning.py only for IPv4.
"""
"""
Your NAT MUST have an "Endpoint-Independent Mapping" behavior for TCP. 
You can refer to the RFC for this requirement, but here is a quick informal summary of it: 
The NAT reuses the port binding for subsequent sessions initiated from the same internal 
IP address and port to any external IP address and port.



"""

from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet import packet_utils
from threading import Timer
import time


log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

class NAT (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    log.debug("Got a new connection for %s" % (connection.dpid,))
    self.connection= connection
    self.mac_to_port = {}
    self.INTERNAL_IP = IPAddr("10.0.1.1")
    self.EXTERNAL_IP = IPAddr("172.64.3.1")
    self.MAC = "00-00-00-00-00-01"
    self.ports_min = 10000
    self.ports_max = 65535
    # natport = (clientip, clientport) 
    self.mappings = {}
    self.nat_ports = {}
    self.arp_entries = {}
    self.arp_entries[IPAddr("172.64.3.21")] = EthAddr("00:00:00:00:00:04")
    self.arp_entries[IPAddr("172.64.3.22")] = EthAddr("00:00:00:00:00:05")
    self.arp_entries[IPAddr("10.0.1.101")] = EthAddr("00:00:00:00:00:01")
    self.arp_entries[IPAddr("10.0.1.102")] = EthAddr("00:00:00:00:00:02")
    self.arp_entries[IPAddr("10.0.1.103")] = EthAddr("00:00:00:00:00:03")    
    self.current_free_port = self.ports_min
    self.listenTo(connection)

  def _handle_PacketIn (self, event):

    log.debug("got a packet on my nat")
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

    def rewriteSourceForNat ():
      log.debug("packet destined for outside")
      ip_packet = packet.next
      tcp_packet = ip_packet.next
      if (ip_packet.srcip, tcp_packet.srcport)
      # create a mapping on the controller for nat port to client port and ip pair
      # rewrite
      # + source port to be free port on NAT
      # + source IP to be NAT external IP
      # + source MAC address ????
      # + destination MAC address from our static arp table
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.EXTERNAL_IP)))
      #remove this ?!!!
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_entries[packet.next.dstip]))     
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def getFreePortOnNat(outbound_packet):
      while True:
        port = random.randint(self.ports_min, self.ports_max)
        log.debug("getFreePortOnNat: Trying to find port %d" % (port))
        if port not in self.mappings:
          return port

    # updating out mac to port mapping
    self.mac_to_port[packet.src] = event.port

    if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
      # Drop LLDP packets 
      # Drop IPv6 packets
      #log.debug("Dropping a packet of type %s" % (ethtype_to_str(packet.type)))
      drop()
      return
    # if packet.next.protocol == packet.next.UDP_PROTOCOL:
    #   log.debug("Dropping a UDP packet: %s" % (packet.next.UDP_PROTOCOL))
    #   drop()
    #   return
    log.debug ("got a packet");
    if (packet.type == packet.ARP_TYPE):
      log.debug("got an arp packet")
      return
    log.debug("destination %s" % (packet.next.dstip.toStr()))
    if packet.next.dstip.toStr() == "172.64.3.1":
      log.debug("re-writing packet destined for nat")
      msg = of.ofp_packet_out()
      #remove this ?!!!
      msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:01")))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr("10.0.1.101")))           
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)      
      return
    # something destined for the outside
    if packet.next.dstip.in_network("172.64.3.0/24"):
      rewriteSourceForNat()
      return

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

class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.mac_to_port = {}
    self.ip_to_mac_arp = {}
    self.listenTo(connection)

  def _handle_PacketIn (self, event):

    # parsing the input packet
    log.debug("got a packet on the bridge")
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
      
      return

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

class p3_nat (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    switch_dpid = dpidToStr(event.dpid)
    log.debug("Switch %s has come up.", dpidToStr(event.dpid))
    if switch_dpid != "00-00-00-00-00-01":
      log.debug("Creating NAT")
      NAT(event.connection)
    else:
      log.debug("Creating learning switch")
      LearningSwitch(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(p3_nat)
