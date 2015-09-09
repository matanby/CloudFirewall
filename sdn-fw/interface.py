import threading
from SimpleXMLRPCServer import SimpleXMLRPCServer

import of_firewall
import utils


class FirewallInterface(object):
	__metaclass__ = utils.Singleton

	def __init__(self):
		self._firewall = of_firewall.Firewall()
		server = SimpleXMLRPCServer(('', 9000), logRequests=False, allow_none=True)
		self._server = server
		server.register_function(self.get_mode, 'get_mode')
		server.register_function(self.set_mode, 'set_mode')
		server.register_function(self.get_active_rules, 'get_active_rules')
		server.register_function(self.add_rule, 'add_rule')
		server.register_function(self.delete_rule, 'delete_rule')
		server.register_function(self.edit_rule, 'edit_rule')
		server.register_function(self.get_events, 'get_events')
		server.register_function(self.get_total_bandwidth, 'get_total_bandwidth')
		server.register_function(self.set_mode, 'set_mode')
		self._server_thread = threading.Thread(target=server.serve_forever)

	def get_mode(self):
		return self._firewall.mode.name

	def set_mode(self, mode):
		try:
			mode = of_firewall.Mode(mode)
		except:
			raise ValueError('Invalid mode: ' % mode)

		self._firewall.set_mode(of_firewall.Mode(mode))

	def get_active_rules(self):
		return [rule.as_dict() for rule in self._firewall.active_rules]

	def add_rule(self, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		rule = self._parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		self._firewall.add_rule(rule)
		return rule.as_dict()

	def delete_rule(self, rule_number):
		deleted_rule = self._firewall.remove_rule(rule_number)
		return deleted_rule.as_dict()

	def edit_rule(self, rule_number, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		rule = self._parse_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		old_rule = self._firewall.edit_rule(rule_number, rule)
		old_rule.as_dict()

	def get_events(self, start_time, end_time):
		return self._firewall.get_events(start_time, end_time)

	def get_total_bandwidth(self, start_time, end_time):
		total_bw = self._firewall.get_total_bandwidth(start_time, end_time)
		return {str(k): v for k, v in total_bw.iteritems()}

	def start_serve_loop(self):
		self._server_thread.daemon = True
		self._server_thread.start()

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

		if isinstance(src_port, str) and '-' not in src_port and '*' not in src_port:
			src_port = int(src_port)

		if isinstance(dst_port, str) and '-' not in dst_port and '*' not in dst_port:
			dst_port = int(dst_port)

		return of_firewall.Rule(
			direction=direction,
			src_ip=src_ip,
			dst_ip=dst_ip,
			protocol=protocol,
			src_port=src_port,
			dst_port=dst_port
		)
