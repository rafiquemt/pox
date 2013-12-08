a#!/usr/bin/env python

"""
Start up a topology
"""

import os.path
import sys

from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, Host
from mininet.topo import Topo
from mininet.util import quietRun, customConstructor

static_arp = False
auto_mac = False
controller_ip = "127.0.0.1"

IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

SWITCHDEF = 'ovsk'
SWITCHES = { 'ovsk': OVSKernelSwitch }

HOSTDEF = 'proc'
HOSTS = { 'proc': Host }

LINKDEF = 'default'
LINKS = { 'default': Link,
          'tc': TCLink }

CONTROLLERS = {'remote': RemoteController}


class NatTopo (Topo):
    "NAT Topology"

    def __init__(self, **opts):

        Topo.__init__(self, **opts)

        # Add hosts and switches
        server1 = self.addHost('server1')
        server2 = self.addHost('server2')
        client1 = self.addHost('client1')
        client2 = self.addHost('client2')
        client3 = self.addHost('client3')
        nat = self.addSwitch('sw0')
        bridge = self.addSwitch('sw1')

        # Add links
        for h in client1, client2, client3:
            self.addLink(h, nat)
        for h in server1, server2, nat:
            self.addLink(h, bridge)

def starthttp(host):
    "Start simple Python web server on servers"
    info( '*** Starting SimpleHTTPServer on host', host, '\n')
    host.cmd('cd ./http_%s/; nohup python ./webserver.py &' % (host.name))

def stophttp():
    "Stop simple Python web server on servers"
    info( '*** Shutting down stale SimpleHTTPServer', 
        quietRun("pkill -9 -f SimpleHTTPServer"), '\n')
    info( '*** Shutting down stale SimpleHTTPServer', 
        quietRun("pkill -9 -f webserver.py"), '\n')

def setclient(host):
    "set the client base directory"
    host.cmd('mkdir ./%s/; cd ./%s/' % (host.name, host.name))

def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if (host.name == 'server1' or host.name == 'server2'):
        routeip = IP_SETTING['sw0-eth2']
    elif (host.name == 'client1' or 
        host.name == 'client2' or
        host.name == 'client3'):
        routeip = IP_SETTING['sw0-eth1']

    print host.name, routeip
    host.cmd('route add %s/32 dev %s-eth0' % (routeip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routeip, host.name))

def load_ip_setting():
    if (not os.path.isfile(IPCONFIG_FILE)):
        return -1
    with open(IPCONFIG_FILE, 'r') as file:
        for line in file:
            name, ip = line.split()
            print name, ip
            IP_SETTING[name] = ip
        return 0

def start_mininet():
    
    stophttp()
    ret = load_ip_setting()
    if (ret == -1):
        sys.exit("Couldn't load config file for ip addresses, check wether %s exists" % IPCONFIG_FILE)
    else:
        info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)

    topo = NatTopo()
    link = customConstructor( LINKS, LINKDEF )
    switch = customConstructor( SWITCHES, SWITCHDEF )
    host = customConstructor( HOSTS, HOSTDEF )
    controller = customConstructor( CONTROLLERS, 'remote,ip=%s' % controller_ip )

    mn = Mininet( topo=topo, 
            switch=switch,
            host=host,
            controller=controller, 
            link=link,
            autoSetMacs=auto_mac,
            listenPort=6634)
    mn.start()

    # set hosts ip address
    server1, server2, client1, client2, client3, nat = mn.get('server1', 'server2', 'client1', 'client2', 'client3', 'sw0')
    
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/8' % IP_SETTING['server1'])
    s2intf = server2.defaultIntf()
    s2intf.setIP('%s/8' % IP_SETTING['server2'])

    c1intf = client1.defaultIntf()
    c1intf.setIP('%s/8' % IP_SETTING['client1'])
    c2intf = client2.defaultIntf()
    c2intf.setIP('%s/8' % IP_SETTING['client2'])
    c3intf = client3.defaultIntf()
    c3intf.setIP('%s/8' % IP_SETTING['client3'])

    # add default route
    for host in client1, client2, client3, server1, server2:
        set_default_route(host)

    # initialize static arp
    if static_arp:
        gw_int_ip = IP_SETTING['sw0-eth1']
        gw_ext_ip = IP_SETTING['sw0-eth2']

        client1.setARP(ip = client2.IP(), mac = client2.MAC())
        client1.setARP(ip = client3.IP(), mac = client3.MAC())
        client1.setARP(ip = gw_int_ip, mac = nat.intf(intf='sw0-eth1').MAC())

        client2.setARP(ip = client1.IP(), mac = client1.MAC())
        client2.setARP(ip = client3.IP(), mac = client3.MAC())
        client2.setARP(ip = gw_int_ip, mac = nat.intf(intf='sw0-eth2').MAC())

        client3.setARP(ip = client1.IP(), mac = client1.MAC())
        client3.setARP(ip = client2.IP(), mac = client2.MAC())
        client3.setARP(ip = gw_int_ip, mac = nat.intf(intf='sw0-eth3').MAC())

        server1.setARP(ip = server2.IP(), mac = server2.MAC())
        server1.setARP(ip = gw_ext_ip, mac = nat.intf(intf='sw0-eth4').MAC())

        server2.setARP(ip = server1.IP(), mac = server1.MAC())
        server2.setARP(ip = gw_ext_ip, mac = nat.intf(intf='sw0-eth4').MAC())

    starthttp(server1)
    starthttp(server2)
    setclient(client1)
    setclient(client2)
    setclient(client3)

    CLI(mn)

    stophttp()
    mn.stop()

if __name__ == '__main__':

    for arg in sys.argv:
        if (arg == '--arp'):
            static_arp = True
        elif (arg == '--mac'):
            auto_mac = True
        elif (arg.startswith('--cip')):
            token = arg.split('=')
            controller_ip = token[1]

    setLogLevel('info')
    start_mininet()

