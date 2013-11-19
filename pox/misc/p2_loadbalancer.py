"""
Author Tariq Rafique
based on work by Junaid Khalid (CSEP561 site)

This is a simple load balancer. it will overwrite the destination packet
"""

from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = of.OFP_FLOW_PERMANENT
IDLE_TIMEOUT = of.OFP_FLOW_PERMANENT

class Server ():
  def __init__(self, ip_address, mac_address, port, currentLoad):
    self.ip = ip_address
    self.mac = mac_address
    self.port = port
    self.currentLoad = currentLoad

class LoadBalancer (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    """
      array of host IPs and number of clients. keep next available client to use
    """    

    self.mac_to_port = {}
    self.ip_to_mac_arp = {}
    self.VIP = IPAddr("10.0.0.100")
    self.VIP_MAC = EthAddr("FF:FF:FF:FF:FF:00")
    self.mac_to_ip = {}
    self.server_mac_to_ip = [None] * 5
    self.server_mac_to_ip[0] = Server("10.0.0.6", "00:00:00:00:00:06", 6, 0)
    self.server_mac_to_ip[1] = Server("10.0.0.7", "00:00:00:00:00:07", 7, 0)
    self.server_mac_to_ip[2] = Server("10.0.0.8", "00:00:00:00:00:08", 8, 0)
    self.server_mac_to_ip[3] = Server("10.0.0.9", "00:00:00:00:00:09", 9, 0)
    self.server_mac_to_ip[4] = Server("10.0.0.10", "00:00:00:00:00:0a", 10, 0)    
    self.nextHost = 0
    self.client_ips = {}
    self.client_to_server = {}
    self.listenTo(connection)



  def _handle_PacketIn (self, event):
    # add a rule to map a certain client to a server
    # add a rule in the reverse direction. when the source is the servers, rewrite 
    # the source to be virtual IP

    # parsing the input packet
    packet = event.parse()

    def getNextAvailableServer(clientIP):
      if clientIP in self.client_to_server:
        return self.client_to_server[clientIP]
      server = self.server_mac_to_ip[self.nextHost]
      self.client_to_server[clientIP] = server
      self.nextHost = (self.nextHost + 1) % len(self.server_mac_to_ip)
      log.debug("going to load balance client %s to server %s" % (clientIP, server.ip))
      return server

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

    def installRuleForToLoadBalance(server, client_ip, incoming_packet):
      msg = of.ofp_flow_mod()
      # overwrite the destination IP and MAC address to be that of the selected server

      msg.match = of.ofp_match.from_packet(incoming_packet, event.port)
      server.port = self.mac_to_port[EthAddr(server.mac)]
      log.debug("found %s at port %s" % (server.mac, server.port))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(server.mac)))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(server.ip)))
      msg.actions.append(of.ofp_action_output(port = server.port))
      msg.data = event.ofp
      msg.idle_timeout = IDLE_TIMEOUT
      msg.hard_timeout = HARD_TIMEOUT
      log.debug("installing flow to rewrite dest (%s, %s) for packets from %s" % (server.mac, server.ip, client_ip))
      self.connection.send(msg)  
      return

    # updating out mac to port mapping
    self.mac_to_port[packet.src] = event.port
    log.debug("port **** %s" % (event.port,))

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      log.debug("Dropping a packet of type %s" % (packet.type,))
      drop()
      return
    log.debug ("got a packet: %s->%s" % (packet.src,packet.dst));

    if (packet.type == packet.ARP_TYPE):
      log.debug("ERROR: shouldn't happen ******* got an arp packet. we're using static arp entries")     
      return

    if packet.next.dstip == self.VIP:
      log.debug("got a request to VIP")
      # find a host to go to
      server_to_use = getNextAvailableServer(packet.next.srcip)
      # install a rule to send it to the next available server
      installRuleForToLoadBalance(server_to_use, packet.next.srcip, packet)
      return
    else: #assume that the packet is going from servers to one of the clients
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      destination_port = self.mac_to_port[packet.dst]
      msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.VIP_MAC)))
      msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.VIP)))
      msg.actions.append(of.ofp_action_output(port = destination_port))
      msg.data = event.ofp
      msg.idle_timeout = IDLE_TIMEOUT
      msg.hard_timeout = HARD_TIMEOUT
      log.debug("installing flow to rewrite src to (%s, %s) for packets from %s" % 
        (self.VIP_MAC, self.VIP, packet.next.srcip))
      self.connection.send(msg)      
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
      msg.idle_timeout = IDLE_TIMEOUT
      msg.hard_timeout = HARD_TIMEOUT
      log.debug("installing flow for %s.%i -> %s.%i" %
        (packet.src, event.port, packet.dst, toInstallPort))
      self.connection.send(msg)

class p2_loadbalancer (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancer(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(p2_loadbalancer)
