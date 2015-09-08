import Pyro4

import ipc
import of_firewall

def get_proxy():
	return ipc.get_proxy_by_name('firewall')


class FirewallInterface(object):
	def __init__(self):
		self._firewall = of_firewall.Firewall()

	@Pyro4.expose()
	def get_mode(self):
		return self._firewall.mode.name

	@Pyro4.expose()
	def set_mode(self, mode):
		try:
			mode = of_firewall.Mode(mode)
		except:
			raise ValueError('Invalid mode: ' % mode)

		self._firewall.set_mode(of_firewall.Mode(mode))

	@Pyro4.expose()
	def get_active_rules(self):
		return [rule.as_dict() for rule in self._firewall.active_rules]

	@Pyro4.expose()
	def add_rule(self, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		rule = self._parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		self._firewall.add_rule(rule)

	@Pyro4.expose()
	def delete_rule(self, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		rule = self._parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		self._firewall.remove_rule(rule)

	@Pyro4.expose()
	def edit_rule(self, rule_number, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		rule = self._parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		self._firewall.edit_rule(rule_number, rule)

	@Pyro4.expose()
	def get_events(self, start_time, end_time):
		return self._firewall.get_events(start_time, end_time)

	@staticmethod
	def _parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port):
		try:
			direction = of_firewall.Direction(direction)
		except:
			raise ValueError('Invalid direction: %s' % direction)

		try:
			protocol = of_firewall.Protocol(protocol)
		except:
			raise ValueError('Invalid protocol: %s' % protocol)

		return of_firewall.Rule(
			direction=direction,
			src_ip=src_ip,
			dst_ip=dst_ip,
			protocol=protocol,
			src_port=src_port,
			dst_port=dst_port
		)


