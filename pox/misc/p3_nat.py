"""
Author Tariq Rafique
based on work by Junaid Khalid (CSEP561 site)

This is a NAT and a learning switch

"""
"""
Your NAT MUST have an "Endpoint-Independent Mapping" behavior for TCP. 
You can refer to the RFC for this requirement, but here is a quick informal summary of it: 
The NAT reuses the port binding for subsequent sessions initiated from the same internal 
IP address and port to any external IP address and port.

client1 wget http://172.64.3.21:8000/index.html


"""

from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.openflow import *
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet import packet_utils
from threading import Timer
from pox.lib.packet import *
import time
import random


log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
NAT_MAC =  EthAddr("00-00-00-00-01-00")

class TCPSTATE:
  INPROCESS_SYN1_SENT = 0
  ESTABLISHED_ACK1_SENT = 1

class NAT (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    log.debug("Got a new connection for %s" % (connection.dpid,))
    self.connection= connection
    self.mac_to_port = {}
    self.INTERNAL_IP = IPAddr("10.0.1.1")
    self.INTERNAL_NETWORK_RANGE = "10.0.1.0/24"
    self.EXTERNAL_IP = IPAddr("172.64.3.1")
    self.MAC = NAT_MAC
    self.EXTERNAL_NETWORK_PORT = 4
    self.ports_min = 10000
    self.ports_max = 65535
    # natport = (clientip, clientport) 
    self.tcp_state = {} # (srcip, srcport, dstip, dstport) -> TCPState
    self.forward_mappings = {} # (srcip, srcport) -> NatPort#
    self.reverse_mappings = {} # NatPort -> (srcip, srcport)
    self.inprocess_timeout = 10
    self.established_timeout = 15

    self.arp_entries = {}
    self.arp_entries[IPAddr("172.64.3.21")] = EthAddr("00:00:00:00:00:04")
    self.arp_entries[IPAddr("172.64.3.22")] = EthAddr("00:00:00:00:00:05")
    self.arp_entries[IPAddr("10.0.1.101")] = EthAddr("00:00:00:00:00:01")
    self.arp_entries[IPAddr("10.0.1.102")] = EthAddr("00:00:00:00:00:02")
    self.arp_entries[IPAddr("10.0.1.103")] = EthAddr("00:00:00:00:00:03")    
    self.current_free_port = self.ports_min
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

    def rewriteSourceForNat (ip_packet, tcp_packet, nat_port):
      # create a mapping on the controller for nat port to client port and ip pair
      # rewrite
      # + source port to be free port on NAT
      # + source IP to be NAT external IP
      # + source MAC address ????
      # + destination MAC address from our static arp table
      if (ip_packet.srcip, tcp_packet.srcport) in self.forward_mappings:
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_entries[ip_packet.dstip]))
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.EXTERNAL_IP))
        msg.actions.append(of.ofp_action_tp_port.set_src(self.mappings[ip_packet.srcip, tcp_packet.srcport]))
        msg.actions.append(of.ofp_action_output(port = self.EXTERNAL_NETWORK_PORT))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)
        pass

    def getFreePortOnNat(outbound_packet):
      while True:
        port = random.randint(self.ports_min, self.ports_max)
        log.debug("getFreePortOnNat: Trying to find port %d" % (port))
        if port not in self.reverse_mappings:
          return port

    def getTCPMapping(ip_packet):
      tcp_packet = ip_packet.next
      if (ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport) in self.forward_mappings:
        return (self.tcp_state[(ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport)], "forward")
      elif (ip_packet.dstip, tcp_packet.dstport, ip_packet.srcip, tcp_packet.srcport) in self.forward_mappings:
        return (self.tcp_state[(ip_packet.dstip, tcp_packet.dstport, ip_packet.srcip, tcp_packet.srcport)], "reverse")
      else:
        return None

    def installRuleToRewriteDestinationToBeClient(ip_packet, tcp_packet):
      clientip_port = self.reverse_mappings[tcp_packet.dstport]
      if clientip_port is None:
        log.debug("Dropping an outside packet at the NAT as we don't have any existing mapping to a client")
        drop()
        return

      client_ip = clientip_port[0]
      client_port = clientip_port[1]

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      # change destination ip, mac and port to be that of the client that initiated this request
      destination_mac = self.arp_entries[client_ip]
      msg.actions.append(of.ofp_action_dl_addr.set_dst(destination_mac))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
      msg.actions.append(of.ofp_action_tp_port.set_dst(client_port))
      msg.actions.append(of.ofp_action_output(port = self.mac_to_port[destination_mac]))
      msg.data = event.ofp
      msg.idle_timeout = 5
      msg.hard_timeout = 5
      log.debug("installing flow to rewrite dst to be (%s, %s) for packets from (%s, %s) for nat port %s" % (client_ip, client_port, ip_packet.srcip, tcp_packet.srcport, tcp_packet.dstport))
      self.connection.send(msg)  

    def installRuleToRewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port):
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_entries[ip_packet.dstip]))
      msg.actions.append(of.ofp_action_dl_addr.set_src(self.MAC))
      msg.actions.append(of.ofp_action_nw_addr.set_src(self.EXTERNAL_IP))
      msg.actions.append(of.ofp_action_tp_port.set_src(nat_port))
      msg.actions.append(of.ofp_action_output(port = self.EXTERNAL_NETWORK_PORT))
      msg.data = event.ofp
      msg.idle_timeout = 5
      msg.hard_timeout = 5
      log.debug("installing flow to rewrite src to be (%s, %s) for packets from (%s, %s)" % (self.EXTERNAL_IP, nat_port, ip_packet.srcip, tcp_packet.srcport))
      self.connection.send(msg)  

    if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
      # Drop LLDP packets 
      # Drop IPv6 packets
      log.debug("Dropping a packet of type %s" % (packet_utils.ethtype_to_str(packet.type)))
      drop()
      return
    # if packet.next.protocol == packet.next.UDP_PROTOCOL:
    #   log.debug("Dropping a UDP packet: %s" % (packet.next.UDP_PROTOCOL))
    #   drop()
    #   return

    if (packet.type == packet.ARP_TYPE):
      log.debug("got an arp packet")
      return

    log.debug ("got a packet on my nat at port: %s" % (event.port))
    
    ip_packet = packet.next
    # *************************************************** START
    if self.isForExternalNetwork(ip_packet):

      tcp_packet = ip_packet.next
      srcdst_quad = (ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport)
      srcdst_pair = (ip_packet.srcip, tcp_packet.srcport)
      # if tcp connection is in process, keep state of tcp connection and keep forwarding packets as necessary
      # get a port mapping on the NAT. timeout that mapping in 300 seconds
      tcp_mapping_found = getTCPMapping(ip_packet)
      if tcp_mapping_found is None:
        if tcp_packet.SYN:
          nat_port = getFreePortOnNat(ip_packet)
          self.tcp_state[srcdst_quad] = TCPSTATE.INPROCESS_SYN1_SENT
          self.forward_mappings[srcdst_pair] = nat_port
          self.reverse_mappings[nat_port] = srcdst_pair
          installRuleToRewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port)
          pass
        else:
          log.debug("********** TCP messed up******")
          pass
      else:
        if tcp_mapping_found[0] == TCPSTATE.ESTABLISHED_ACK1_SENT:
          log.debug("shouldnt see anything here. got a packet for an established tcp connection")
          pass
        elif tcp_mapping_found[1] == "forward":
          log.debug("shouldnt see anything here. got a packet for an established tcp connection")
          if tcp_packet.ACK:
            nat_port = self.forward_mappings[srcdst_pair]
            # the packet is an ack in the forward direction, then connection moves to established state
            self.tcp_state[srcdst_quad] = TCPSTATE.ESTABLISHED_ACK1_SENT
            installRuleToRewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port)
            pass
          else:

            pass
          pass
        pass

      # schedule a timer to kill this connection in the longer timeout



      
      # if tcp connection is established
      # install a rule that timesout after 7440 seconds
      pass
    elif packet.next.dstip.toStr() == self.EXTERNAL_IP:
      # packet is destined for a client behind the NAT, 
      # basically modify destination MAC and IP based on reverse bindings already established. 
      tcp_packet = ip_packet.next
      installRuleToRewriteDestinationToBeClient(ip_packet, tcp_packet)
      pass
    elif packet.next.dstip.in_network(self.INTERNAL_NETWORK_RANGE):
      # updating out mac to port mapping
      self.mac_to_port[packet.src] = event.port
      # do l2 learning switch rules
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
        pass
      pass
    # =================================================== END



  def isForExternalNetwork (self, ip_packet):
    if isinstance(ip_packet, ipv4):
      return (ip_packet.dstip.toStr() != "172.64.3.1" and ip_packet.dstip.in_network("172.64.3.0/24"))

class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.mac_to_port = {}
    self.ip_to_mac_arp = {}
    self.ip_to_port = {}
    self.BRIDGE_EXTERNAL_NETWORK_RANGE = "10.0.1.0/24"
    self.BRIDGE_NAT_PORT = 3
    self.mac_to_port[NAT_MAC] = self.BRIDGE_NAT_PORT
    self.BRIDGE_NAT_IP = "172.64.3.1"
    self.ip_to_port[IPAddr(self.BRIDGE_NAT_PORT)] = self.BRIDGE_NAT_PORT
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
    if packet.next.dstip.in_network(self.BRIDGE_EXTERNAL_NETWORK_RANGE):
      log.debug("Dropping packet with destination in external network wrt bridge: %s" % (packet.next.dstip.toStr()))
      drop()
      return

    if (packet.type == packet.ARP_TYPE):
      log.debug("got an arp packet")
      
      return

    log.debug ("got a packet on the bridge at port: %s" % (event.port));

    if packet.dst not in self.mac_to_port:
      if packet.next.dstip == self.BRIDGE_NAT_IP:
        self.mac_to_port[packet.dst] = self.BRIDGE_NAT_PORT
        pass
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

class p3_nat (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    conn = event.connection
    if isinstance(conn, of_01.Connection):
      switch_dpid = dpidToStr(event.dpid)
      log.debug("Switch %s has come up.", dpidToStr(event.dpid))
      if switch_dpid != "00-00-00-00-00-01":
        log.debug("Creating NAT")
        NAT(conn)
      else:
        log.debug("Creating learning switch")
        LearningSwitch(conn)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(p3_nat)
