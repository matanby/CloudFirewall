from enum import Enum
import pickle
import pox
import pox.log
import pox.core
import pox.log.color
from pox.core import core
from pox.openflow import libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp

import ipc
import interface
import utils
from of_base import OpenFlowController


class Mode(Enum):
	WhiteList = 'WhiteList'
	BlackList = 'BlackList'
	PassThrough = 'PassThrough'


class Protocol(Enum):
	ICMP = 'ICMP'
	TCP = 'TCP'
	UDP = 'UDP'


class Direction(Enum):
	Incoming = 'Incoming'
	Outgoing = 'Outgoing'


class Action(Enum):
	Blocked = 'Block'
	Allowed = 'Allowed'


class Event(utils.Container):
	def __init__(self, **kwargs):
		self.direction = None
		self.src_ip = None
		self.dst_ip = None
		self.protocol = None
		self.src_port = None
		self.dst_port = None
		self.action = None
		self.time = None

		self._set_attributes(**kwargs)


class Rule(utils.Container):
	def __init__(self, **kwargs):
		self.direction = None
		self.src_ip = None
		self.dst_ip = None
		self.protocol = None
		self.src_port = None
		self.dst_port = None

		self._set_attributes(**kwargs)
		self.direction = Direction(self.direction)
		self.protocol = Protocol(self.protocol)

	def matches(self, direction, source_ip, dest_ip, protocol, src_port, dst_port):
		# Direction
		if self.direction != direction:
			return False

		# Protocol
		if self.protocol != protocol:
			return False

		# Source IP
		if '-' in self.src_ip:
			source_ip_start, source_ip_end = self.src_ip.replace(' ', '').split('-')
		else:
			source_ip_start, source_ip_end = self.src_ip, self.src_ip

		if not source_ip_start <= source_ip <= source_ip_end and source_ip_start != '*':
			return False

		# Source IP
		if '-' in self.dst_ip:
			dest_ip_start, dest_ip_end = self.dst_ip.replace(' ', '').split('-')
		else:
			dest_ip_start, dest_ip_end = self.dst_ip, self.dst_ip

		if not dest_ip_start <= dest_ip <= dest_ip_end and dest_ip_start != '*':
			return False

		# Source port
		if isinstance(self.src_port, str) and '-' in self.src_port:
			src_port_start, source_port_end = self.src_port.replace(' ', '').split('-')
			src_port_start, source_port_end = int(src_port_start), int(source_port_end)
		else:
			src_port_start, source_port_end = self.src_port, self.src_port

		if not src_port_start <= src_port <= source_port_end and src_port_start != '*':
			return False

		# Destination port
		if isinstance(self.dst_port, str) and '-' in self.dst_port:
			dst_port_start, source_port_end = self.dst_port.replace(' ', '').split('-')
			dst_port_start, source_port_end = int(self.dst_port), int(self.dst_port)
		else:
			dst_port_start, source_port_end = self.dst_port, self.dst_port

		if not dst_port_start <= dst_port <= source_port_end and dst_port_start != '*':
			return False

		return True


class Firewall(OpenFlowController):
	__metaclass__ = utils.Singleton

	CONFIG_FILE_PATH = 'config.yaml'
	EVENTS_FILE = 'events.bin'

	def __init__(self):
		super(Firewall, self).__init__()
		self._incoming_port = None
		self._outgoing_port = None
		self._mode = None
		self._flow_active_time_secs = None
		self._firewall_dpid = None
		self._blacklist_rules = None
		self._whitelist_rules = None
		self._load_configuration()
		self._events = self._load_events()

	def set_mode(self, new_mode):
		self._mode = new_mode
		self._dump_configuration()
		self._switches[self._firewall_dpid].remove_flow_mod()

	def add_rule(self, rule):
		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			self._blacklist_rules.add(rule)

		if self._mode == Mode.WhiteList:
			self._whitelist_rules.add(rule)

		self._dump_configuration()
		self._switches[self._firewall_dpid].remove_flow_mod()

	def remove_rule(self, rule_number):
		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			self._blacklist_rules.pop(rule_number)

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			self._whitelist_rules.pop(rule_number)

		self._dump_configuration()
		self._switches[self._firewall_dpid].remove_flow_mod()

	def edit_rule(self, rule_number, rule):
		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			self._blacklist_rules.pop(rule_number)
			self._blacklist_rules.add(rule)

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			self._whitelist_rules.pop(rule_number)
			self._whitelist_rules.add(rule)

		self._dump_configuration()
		self._switches[self._firewall_dpid].remove_flow_mod()

	def get_events(self, start_time, end_time):
		return [event for event in self._events if event]

	def _handle_packet(self, event):
		# Ignore events that are related to other switches in the network.
		if event.dpid != self._firewall_dpid:
			return

		packet = event.parsed  # Packet is the original L2 packet sent by the switch
		packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

		if packet_in.in_port not in [self._incoming_port, self._outgoing_port]:
			self._log.warning('Received a packet from an unfamiliar port: %s' % packet_in.in_port)
			return

		if self._is_flow_allowed(packet_in.in_port, packet):
			out_port = self._outgoing_port if packet_in.in_port == self._incoming_port else self._incoming_port
		else:
			# install rule in the switch that ignores that packet
			out_port = of.OFPP_NONE

		action = of.ofp_action_output(port=out_port)
		match = of.ofp_match.from_packet(packet, in_port=packet_in.in_port)
		self._switches[event.dpid].add_flow_mod(action, match, buffer_id=packet_in.buffer_id, idle_timeout=self._flow_active_time_secs)

	def _is_flow_allowed(self, input_port, packet):
		# TODO: allow ICMP blocking
		if not isinstance(packet.next, ipv4) or not (isinstance(packet.next.next, tcp) or isinstance(packet.next.next, udp)):
			return True

		# Find the direction of the packet.
		if input_port == self._outgoing_port:
			direction = Direction.Incoming
		elif input_port == self._incoming_port:
			direction = Direction.Outgoing
		else:
			return False

		# Find the protocol of the packet.
		if isinstance(packet.next.next, tcp):
			protocol = Protocol.TCP
		else:
			protocol = Protocol.UDP

		src_ip = str(packet.payload.srcip)
		dst_ip = str(packet.payload.dstip)
		protocol = protocol
		src_port = packet.next.next.srcport
		dst_port = packet.next.next.dstport

		matches_packet = lambda rule: rule.matches(direction, src_ip, dst_ip, protocol, src_port, dst_port)

		if self._mode == Mode.PassThrough:
			return True

		elif self._mode == Mode.BlackList:
			return filter(matches_packet, self._blacklist_rules) == []

		elif self._mode == Mode.WhiteList:
			return filter(matches_packet, self._whitelist_rules) != []

	def _load_configuration(self):
		config = utils.load_yaml(self.CONFIG_FILE_PATH)
		self._incoming_port = config['physical_ports']['incoming']
		self._outgoing_port = config['physical_ports']['outgoing']
		self._mode = Mode(config['mode'])
		self._flow_active_time_secs = config['flow_active_time_secs']
		self._firewall_dpid = config['firewall_dpid']
		self._blacklist_rules = [Rule(**rule_dict) for rule_dict in config['blacklist_rules']]
		self._whitelist_rules = [Rule(**rule_dict) for rule_dict in config['whitelist_rules']]

	def _dump_configuration(self):
		config = {
			'physical_ports': {
				'incoming': self._incoming_port,
				'outgoing': self._outgoing_port,
			},
			'mode': self._mode.name,
			'flow_active_time_secs': self._flow_active_time_secs,
			'firewall_dpid': self._firewall_dpid,
			'blacklist_rules': [rule.as_dict() for rule in self._blacklist_rules],
			'whitelist_rules': [rule.as_dict() for rule in self._whitelist_rules],
		}

		utils.dump_yaml(self.CONFIG_FILE_PATH, config)

	def _load_events(self):
		try:
			with open(self.EVENTS_FILE ,'r') as f:
				return pickle.loads(f.read())
		except:
			return []

	@property
	def mode(self):
		return self._mode

	@property
	def active_rules(self):
		if self._mode == Mode.BlackList:
			return self._blacklist_rules
		if self._mode == Mode.WhiteList:
			return self._whitelist_rules
		if self._mode == Mode.PassThrough:
			return []


def init_logger():
	"""
	Enable color logging with human friendly formatting.
	"""

	LOG_FORMAT = "@@@bold@@@level%(asctime)s - %(levelname)s@@@bold@@@level\t- %(name)s - %(message)s@@@normal@@@reset"

	# Enable color logging with human friendly formatting.
	pox.log.color.launch()
	pox.log.launch(format=LOG_FORMAT)

	# Set the default log handler's stream as STDOUT
	# instead of STDERR (to enable color logging in PyCharm)
	from pox.core import _default_log_handler as dlh
	from sys import stdout
	dlh.stream = stdout


def launch():
	"""
	Starts the component.
	"""

	init_logger()
	ipc.init()
	ipc.start_request_loop()
	ipc.register_service(interface.FirewallInterface(), 'firewall')

	# Register instances of the specific DataCenterController and Discovery to POX's core.
	core.registerNew(Firewall)
