#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class MyTopology(Topo):
	"""A basic topology
	"""
	def __init__(self):
        	Topo.__init__(self)

        	#set up topology here
        	switch= self.addSwitch('s1') ## Add a switch

	        ##adding host    
        	host1 = self.addHost('h1') 
        	host2 = self.addHost('h2')
		host3 = self.addHost('h3')          
		host4 = self.addHost('h4')

        	#connecting it to links   
        	self.addLink(host1, switch)
		self.addLink(host2, switch)
		self.addLink(host3, switch)
		self.addLink(host4, switch)                  
              

if __name__ == '__main__':
            	"""If this script is run as an executable (by chmod +x), this is wh                at it will do
            	"""
             	topo = MyTopology()        #Creates The topology 
             	net = Mininet(topo=topo)   #loads the topology
             	net.start()                #Starts Mininet

             	# Comands here will run on the simulated topology 
             	CLI(net)
             	net.stop()
