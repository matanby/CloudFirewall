from mininet.topo import Topo


class Edge:
	"""
	Represents an edge between two entities.
	"""

	def __init__(self, left, right):
		self.left = left
		self.right = right


class TwoNetworksTopology(Topo):
	"""
	A simple networks that consists of two switches that are both connected to
	the same firewall. In addition, to each switch connects a single host.
	"""

	def __init__(self):
		Topo.__init__(self)

		# Core switches:
		# The DPID of core switches should be in the range [100,199].
		switches = [
			self.addSwitch('s101'),
			self.addSwitch('s102'),
		]

		firewall = self.addSwitch('s200')

		# Hosts
		server_hosts = [
			self.addHost('h1'),
			self.addHost('h2'),
			self.addHost('h3'),
			self.addHost('h4'),
		]

		# Edges
		edges = [
			# s101 -> firewall <- s102
			Edge(switches[0], firewall),
			Edge(switches[1], firewall),

			# h1, h2 -> s101.
			Edge(server_hosts[0], switches[0]),
			Edge(server_hosts[1], switches[0]),

			# h3, h4 -> s102.
			Edge(server_hosts[2], switches[1]),
			Edge(server_hosts[3], switches[1]),

		]

		for edge in edges:
			self.addLink(edge.left, edge.right, bw=100)


topos = {
	'TwoNetworksTopology': TwoNetworksTopology,
}


