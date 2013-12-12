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
import pox.lib.packet as pkt
from threading import Timer
from pox.lib.packet import *
import time
import random
import threading


log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
ESTABLISHED_TCP_IDLE_TIMEOUT = 7440
INPROGRESS_TCP_TIMEOUT = 300

NAT_MAC =  EthAddr("00-00-00-00-01-00")

class TCPSTATE:
  INPROCESS_SYN1_SENT = 0
  ESTABLISHED_ACK1_SENT = 1
  ESTABLISHED_REVERSERULE_INSTALLED = 2

class NAT (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    log.debug("Got a new connection for %s" % (connection.dpid,))
    self.connection= connection
    self.mac_to_port = {}
    self.INTERNAL_IP = IPAddr("10.0.1.1")
    self.INTERNAL_NETWORK_RANGE = "10.0.1.0/24"
    self.EXTERNAL_NETWORK_RANGE = "172.64.3.0/24"
    self.EXTERNAL_IP = IPAddr("172.64.3.1")
    self.MAC = NAT_MAC
    self.EXTERNAL_NETWORK_PORT = 4
    self.ports_min = 10000
    self.ports_max = 65535
    # natport = (clientip, clientport) 
    self.tcp_state = {} # (srcip, srcport, dstip, dstport) -> TCPState
    self.forward_mappings = {} # (srcip, srcport) -> NatPort#
    self.reverse_mappings = {} # NatPort -> (srcip, srcport)
    self.inprocess_timeout = INPROGRESS_TCP_TIMEOUT
    self.established_idle_timeout = ESTABLISHED_TCP_IDLE_TIMEOUT
    self.filtering_list = ["172.64.3.22"] # don't allow communication with server2

    self.arp_entries = {}
    self.arp_entries[IPAddr("172.64.3.21")] = EthAddr("00:00:00:00:00:04")
    self.arp_entries[IPAddr("172.64.3.22")] = EthAddr("00:00:00:00:00:05")
    self.arp_entries[IPAddr("10.0.1.101")] = EthAddr("00:00:00:00:00:01")
    self.arp_entries[IPAddr("10.0.1.102")] = EthAddr("00:00:00:00:00:02")
    self.arp_entries[IPAddr("10.0.1.103")] = EthAddr("00:00:00:00:00:03")    
    self.current_free_port = self.ports_min
    self.listenTo(connection)

  def _handle_FlowRemoved (self, event):
    #clean up: 
    # + forward, reverse mappings
    # + tcp_state 
    match = event.ofp.match
    if (match.nw_dst.toStr() == self.EXTERNAL_IP.toStr()):
      clientip_port = self.reverse_mappings.pop(match.tp_dst)
      log.debug("**** removed reverse mapping at port %d" % match.tp_dst)
      srcdst_quad = (match.nw_src, match.tp_src, clientip_port[0], clientip_port[1])
      #clear out tcp state if it exists
      if srcdst_quad in self.tcp_state:
        self.tcp_state.pop(srcdst_quad)
        log.debug("removing tcp state for: %s", srcdst_quad)
      pass      
    elif match.nw_dst.in_network(self.EXTERNAL_NETWORK_RANGE):
      client_ip = match.nw_src
      client_port = match.tp_src
      nat_port = self.forward_mappings.pop((client_ip, client_port))
      log.debug("**** removed forward mapping (%s,%d->%d)" % 
        (client_ip, client_port, nat_port))
      # clear out tcp state
      srcdst_quad = (client_ip, client_port, match.nw_dst, match.tp_dst)
      if srcdst_quad in self.tcp_state:
        self.tcp_state.pop(srcdst_quad)
        log.debug("removing tcp state for: %s", srcdst_quad)
      pass
    else:
      log.debug("removing random flow. shouldn't happen!")
    return

  def _handle_PacketIn (self, event):
    # parsing the input packet
    packet = event.parse()    
    # updating out mac to port mapping
    self.mac_to_port[packet.src] = event.port

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

    def getFreePortOnNat(outbound_packet):
      while True:
        port = random.randint(self.ports_min, self.ports_max)
        log.debug("getFreePortOnNat: Trying to see if this port is free: %d" % (port))
        if port not in self.reverse_mappings:
          return port

    def installRuleToRewriteDestinationToBeClient(ip_packet, tcp_packet):
      clientip_port = self.reverse_mappings[tcp_packet.dstport]
      if clientip_port is None:
        log.debug("Dropping an outside packet at the NAT as we don't have any existing mapping to a client")
        drop()
        return

      client_ip = clientip_port[0]
      client_port = clientip_port[1]

      msg = of.ofp_flow_mod()
      msg.flags |= of.OFPFF_SEND_FLOW_REM
      #msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_proto = pkt.ipv4.TCP_PROTOCOL,
        in_port = event.port, nw_src = ip_packet.srcip, nw_dst = ip_packet.dstip, tp_dst = tcp_packet.dstport)
      # change destination ip, mac and port to be that of the client that initiated this request
      destination_mac = self.arp_entries[client_ip]
      msg.actions.append(of.ofp_action_dl_addr.set_dst(destination_mac))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
      msg.actions.append(of.ofp_action_tp_port.set_dst(client_port))
      msg.actions.append(of.ofp_action_output(port = self.mac_to_port[destination_mac]))
      msg.data = event.ofp
      msg.idle_timeout = self.established_idle_timeout
      log.debug("installing flow to rewrite dst to be (%s, %s) for packets from (%s, %s) for nat port %s" % (client_ip, client_port, ip_packet.srcip, tcp_packet.srcport, tcp_packet.dstport))
      self.connection.send(msg)  

    def installRuleToRewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port):
      msg = of.ofp_flow_mod()
      msg.flags |= of.OFPFF_SEND_FLOW_REM
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_entries[ip_packet.dstip]))
      #msg.actions.append(of.ofp_action_dl_addr.set_src(self.MAC))
      msg.actions.append(of.ofp_action_nw_addr.set_src(self.EXTERNAL_IP))
      msg.actions.append(of.ofp_action_tp_port.set_src(nat_port))
      msg.actions.append(of.ofp_action_output(port = self.EXTERNAL_NETWORK_PORT))
      msg.data = event.ofp
      msg.idle_timeout = self.established_idle_timeout
      log.debug("installing flow to rewrite src to be (%s, %s) for packets from (%s, %s)" % (self.EXTERNAL_IP, nat_port, ip_packet.srcip, tcp_packet.srcport))
      self.connection.send(msg) 

    def rewriteDestinationToBeClient(ip_packet, tcp_packet):
      clientip_port = self.reverse_mappings.get(tcp_packet.dstport)
      if clientip_port is None:
        log.debug("Dropping an outside packet at the NAT as we don't have any existing mapping to a client")
        drop()
        return

      client_ip = clientip_port[0]
      client_port = clientip_port[1]

      msg = of.ofp_packet_out()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      # change destination ip, mac and port to be that of the client that initiated this request
      destination_mac = self.arp_entries[client_ip]
      msg.actions.append(of.ofp_action_dl_addr.set_dst(destination_mac))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
      msg.actions.append(of.ofp_action_tp_port.set_dst(client_port))
      msg.actions.append(of.ofp_action_output(port = self.mac_to_port[destination_mac]))
      msg.data = event.ofp
      log.debug("rewrite dst to be (%s, %s) for packets from (%s, %s) for nat port %s" % (client_ip, client_port, ip_packet.srcip, tcp_packet.srcport, tcp_packet.dstport))
      self.connection.send(msg)  

    def rewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port):
      msg = of.ofp_packet_out()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_entries[ip_packet.dstip]))
      #msg.actions.append(of.ofp_action_dl_addr.set_src(self.MAC))
      msg.actions.append(of.ofp_action_nw_addr.set_src(self.EXTERNAL_IP))
      msg.actions.append(of.ofp_action_tp_port.set_src(nat_port))
      msg.actions.append(of.ofp_action_output(port = self.EXTERNAL_NETWORK_PORT))
      msg.data = event.ofp
      log.debug("rewrite src to be (%s, %s) for packets from (%s, %s)" % (self.EXTERNAL_IP, nat_port, ip_packet.srcip, tcp_packet.srcport))
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

    log.debug ("")
    log.debug ("**** got a packet on my nat at port: %s" % (event.port))
  
    if packet.next.dstip.in_network(self.INTERNAL_NETWORK_RANGE):
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
        msg.hard_timeout = HARD_TIMEOUT
        msg.idle_timeout = IDLE_TIMEOUT
        log.debug("installing flow for %s.%i -> %s.%i" %
          (packet.src, event.port, packet.dst, toInstallPort))
        self.connection.send(msg)
        pass
      return

    ip_packet = packet.next
    if (ip_packet.dstip.toStr() in self.filtering_list):
      log.debug("Dropping packets destined for %s", ip_packet.dstip)
      drop()
      return
      pass
    tcp_packet = ip_packet.next
    # *************************************************** START NAT stuff
    srcdst_quad = (ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport)
    srcdst_reverse_quad = (ip_packet.dstip, tcp_packet.dstport, ip_packet.srcip, tcp_packet.srcport)
    srcdst_pair = (ip_packet.srcip, tcp_packet.srcport)
    def debugPrintTCPPacket():
      log.debug ("TCP: (%s:%d) -> (%s:%d) Flag: %s" %
        (ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport, tcp_packet.flagsToStr()))

    def installPersistentMappings():
      nat_port = -1
      if self.isForExternalNetwork(ip_packet):
        if srcdst_pair not in self.forward_mappings:
          nat_port = getFreePortOnNat(ip_packet)
          self.forward_mappings[srcdst_pair] = nat_port
          self.reverse_mappings[nat_port] = srcdst_pair
          pass
        else:
          nat_port = self.forward_mappings[srcdst_pair]
          pass

        installRuleToRewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port)
      elif packet.next.dstip.toStr() == self.EXTERNAL_IP:
        # packet is destined for a client behind the NAT, 
        # basically modify destination MAC and IP based on reverse bindings already established. 
        installRuleToRewriteDestinationToBeClient(ip_packet, tcp_packet)
        pass    
      return

    def routePacketsToFromNAT():
      nat_port = -1
      if self.isForExternalNetwork(ip_packet):
        if srcdst_pair not in self.forward_mappings:
          nat_port = getFreePortOnNat(ip_packet)
          self.forward_mappings[srcdst_pair] = nat_port
          self.reverse_mappings[nat_port] = srcdst_pair
          pass
        else:
          nat_port = self.forward_mappings[srcdst_pair]
          pass

        rewriteSourceToBeNAT(ip_packet, tcp_packet, nat_port)
      elif packet.next.dstip.toStr() == self.EXTERNAL_IP:
        # packet is destined for a client behind the NAT, 
        # basically modify destination MAC and IP based on reverse bindings already established. 
        rewriteDestinationToBeClient(ip_packet, tcp_packet)
        pass    
      return

    def removeTCPStateBindingIfTimedout(srcdst_quad_toremove):
      curr_state = self.tcp_state.get(srcdst_quad_toremove)
      if curr_state is None:
        log.debug("***** Problem in removeTCPStateBindingIfTimedout. can't find state for %s" % srcdst_quad_toremove)
      elif curr_state == TCPSTATE.ESTABLISHED_ACK1_SENT or curr_state == TCPSTATE.ESTABLISHED_REVERSERULE_INSTALLED:
        log.debug("Timer fired, but not removing established connection: %s", srcdst_quad_toremove)
      else:
        self.tcp_state.pop(srcdst_quad_toremove)
        log.debug("Timer fired, removing in progress tcp connection: %s",srcdst_quad_toremove)
      return

    #self.tcp_state = {} # (srcip, srcport, dstip, dstport) -> TCPState

    # replace nat IP with client IP if possible
    if ip_packet.dstip.toStr() == self.EXTERNAL_IP:
      # find reverse mapping and generate the reverse quad
      if tcp_packet.dstport in self.reverse_mappings:
        clientip_port = self.reverse_mappings[tcp_packet.dstport]
        srcdst_reverse_quad = (clientip_port[0], clientip_port[1], ip_packet.srcip, tcp_packet.srcport)
        srcdst_quad = (ip_packet.srcip, tcp_packet.srcport, clientip_port[0], clientip_port[1])
      pass

    curr_state = self.tcp_state.get(srcdst_quad)
    forward_direction_conn = True

    debugPrintTCPPacket()

    # find if we're tracking this tcp state and in which direction
    if curr_state is None:
      curr_state = self.tcp_state.get(srcdst_reverse_quad)
      if curr_state is not None:
        forward_direction_conn = False
        pass
      pass

    if curr_state is None:
      log.debug("TCPSTATE none")
      self.tcp_state[srcdst_quad] = TCPSTATE.INPROCESS_SYN1_SENT
      routePacketsToFromNAT()
      #schedule a timer to kill this binding completely if connection isn't established
      t = threading.Timer(self.inprocess_timeout, removeTCPStateBindingIfTimedout, [srcdst_quad] )
      t.start()
      return
      pass
    elif curr_state == TCPSTATE.INPROCESS_SYN1_SENT:
      if forward_direction_conn and tcp_packet.ACK:
        log.debug("TCP State INP: forward")
        self.tcp_state[srcdst_quad] = TCPSTATE.ESTABLISHED_ACK1_SENT
        installPersistentMappings()
        return
        pass
      else:
        log.debug("TCP State INP: reverse")
        routePacketsToFromNAT()
        return
      pass
    elif curr_state == TCPSTATE.ESTABLISHED_ACK1_SENT:
      log.debug("TCP State established: forward rule already installed")    
      if forward_direction_conn:
        routePacketsToFromNAT()
      else:
        installPersistentMappings()
        self.tcp_state[srcdst_quad] = TCPSTATE.ESTABLISHED_REVERSERULE_INSTALLED
      return
    elif curr_state == TCPSTATE.ESTABLISHED_REVERSERULE_INSTALLED:
      log.debug("TCP state established with reverse rule installed")
      routePacketsToFromNAT()
      return
    else:
      log.debug("**** came across an UNKNOWN TCPSTATE ** Shouldn't happen ***")
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
    log.debug ("got a packet on the bridge at port: %s" % (event.port));
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
