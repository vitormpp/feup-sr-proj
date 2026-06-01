#!/usr/bin/env python3
# encoding: utf-8

from seedemu import *

def makeStubAs(emu: Emulator, base: Base, asn: int, exchange: int, hosts_total: int):
    # Create AS and internal network
    network = "net0"
    stub_as = base.createAutonomousSystem(asn)
    stub_as.createNetwork(network)

    # Create a BGP router
    # Attach the router to both the internal and external networks
    router = stub_as.createRouter('router0')
    router.joinNetwork(network)
    router.joinNetwork('ix{}'.format(exchange))

    for counter in range(hosts_total):
       name = 'host_{}'.format(counter)
       host = stub_as.createHost(name)
       host.joinNetwork(network)



hosts_total = 3

###############################################################################
emu     = Emulator()
base    = Base()
routing = Routing()
ebgp    = Ebgp()
ibgp    = Ibgp()
web     = WebService()


###############################################################################

ix103 = base.createInternetExchange(103)
ix103.getPeeringLan().setDisplayName('Miami-103')

###############################################################################
# Create single-homed stub ASes. 
makeStubAs(emu, base, 160, 103, hosts_total)
makeStubAs(emu, base, 161, 103, hosts_total)
makeStubAs(emu, base, 162, 103, hosts_total)

###############################################################################
# Peering via RS (route server). The default peering mode for RS is PeerRelationship.Peer, 
# which means each AS will only export its customers and their own prefixes. 
# We will use this peering relationship to peer all the ASes in an IX.
# None of them will provide transit service for others. 

ebgp.addRsPeers(103, [160, 161, 162])

###############################################################################

# Add layers to the emulator
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(ebgp)
emu.addLayer(ibgp)
emu.addLayer(Ospf())
emu.addLayer(web)

# Save it to a component file, so it can be used by other emulators
emu.dump('base-component.bin')

#emu.render()
#docker = Docker(internetMapEnabled=True)
#emu.compile(docker, './emulators/mini-internet', override = True)

