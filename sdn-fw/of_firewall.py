from enum import Enum
import pickle
import time
import pox
import pox.log
import pox.core
import pox.log.color
from pox.core import core
from pox.openflow import libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp

import interface
import utils
from of_base import OpenFlowController


class Mode(Enum):
	"""
	Represents a firewall's working mode.
	"""

	WhiteList = 'WhiteList'
	BlackList = 'BlackList'
	PassThrough = 'PassThrough'


class Protocol(Enum):
	"""
	Represents L3/L4 protocols.
	"""

	ICMP = 'ICMP'
	TCP = 'TCP'
	UDP = 'UDP'
	TCP_UDP = 'TCP/UDP'


class Direction(Enum):
	"""
	Represents packets directions.
	"""

	Incoming = 'Incoming'
	Outgoing = 'Outgoing'


class Action(Enum):
	"""
	Represents a firewall's action.
	"""

	Blocked = 'Blocked'
	Allowed = 'Allowed'


class Event(utils.Container):
	"""
	Represents an event handled at the firewall.
	"""

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

	def as_dict(self):
		return {
			'direction': self.direction.value,
			'src_ip': self.src_ip,
			'dst_ip': self.dst_ip,
			'protocol': self.protocol.value,
			'src_port': self.src_port,
			'dst_port': self.dst_port,
			'action': self.action.value,
			'time': self.time,
		}


class Rule(utils.Container):
	"""
	Represents a firewall rule.
	"""

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

		if isinstance(self.src_port, str) and '-' not in self.src_port and '*' not in self.src_port:
			self.src_port = int(self.src_port)

		if isinstance(self.dst_port, str) and '-' not in self.dst_port and '*' not in self.dst_port:
			self.dst_port = int(self.dst_port)

	def as_dict(self):
		return {
			'direction': self.direction.value,
			'src_ip': self.src_ip,
			'dst_ip': self.dst_ip,
			'protocol': self.protocol.value,
			'src_port': self.src_port,
			'dst_port': self.dst_port
		}

	def matches(self, direction, source_ip, dest_ip, protocol, src_port, dst_port):
		"""
		Checks if this rule matches a set of packet details.
		"""

		# Direction
		if self.direction != direction:
			return False

		# Protocol
		if self.protocol != Protocol.TCP_UDP and self.protocol != protocol:
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
			dst_port_start, dst_port_end = self.dst_port.replace(' ', '').split('-')
			dst_port_start, dst_port_end = int(dst_port_start), int(dst_port_end)
		else:
			dst_port_start, dst_port_end = self.dst_port, self.dst_port

		if not dst_port_start <= dst_port <= dst_port_end and dst_port_start != '*':
			return False

		return True


class Firewall(OpenFlowController):
	"""
	This class implements an SDN controller which acts as a firewall.
	"""

	__metaclass__ = utils.Singleton

	CONFIG_FILE_PATH = 'config.yaml'
	EVENTS_FILE = 'events.bin'

	def __init__(self):
		self._incoming_port = None
		self._outgoing_port = None
		self._mode = None
		self._flow_active_time_secs = None
		self._time_to_keep_stats_secs = None
		self._firewall_dpid = None
		self._blacklist_rules = None
		self._whitelist_rules = None
		self._active_flows = []
		self._total_bandwidth = {}  # time -> bandwidth (Mbit/sec)
		self._load_configuration()
		self._events = self._load_events()
		super(Firewall, self).__init__()
		self._log.info('Firewall started, initial mode: %s' % self._mode.name)

	def set_mode(self, new_mode):
		"""
		Sets a new firewall working mode.
		"""

		self._log.info('Mode changed to: %s' % new_mode.name)
		self._mode = new_mode
		self._dump_configuration()
		self._remove_all_flow_records()

	def _remove_all_flow_records(self):
		"""
		Removes all active flow records from the controlled SDN switch.
		"""

		self._log.info('Removing all active flow records')
		if self._firewall_dpid in self._switches:
			self._switches[self._firewall_dpid].remove_flow_mod()

	def add_rule(self, rule):
		"""
		Adds a new firewall rule to the active rules set.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			self._log.info('Adding new rule to the blacklist rules set: %s' % rule)
			self._blacklist_rules.append(rule)

		if self._mode == Mode.WhiteList:
			self._log.info('Adding new rule to the whitelist rules set: %s' % rule)
			self._whitelist_rules.append(rule)

		self._dump_configuration()
		self._remove_all_flow_records()

	def remove_rule(self, rule_number):
		"""
		Removes a firewall rule from the active rules set.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			rule = self._blacklist_rules.pop(rule_number)
			self._log.info('Removing rule from the blacklist rules set: %s' % rule)

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			rule = self._whitelist_rules.pop(rule_number)
			self._log.info('Removing rule from the whitelist rules set: %s' % rule)

		self._dump_configuration()
		self._remove_all_flow_records()
		return rule

	def edit_rule(self, rule_number, rule):
		"""
		Edits an exiting firewall rule.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			old_rule = self._blacklist_rules.pop(rule_number)
			self._blacklist_rules.append(rule)
			self._log.info('Replaced rule from the blacklist rules set: \n old: %s\n new: %s' % (old_rule, rule))

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			old_rule = self._whitelist_rules.pop(rule_number)
			self._whitelist_rules.append(rule)
			self._log.info('Replaced rule from the whitelist rules set: \n old: %s\n new: %s' % (old_rule, rule))

		self._dump_configuration()
		self._remove_all_flow_records()
		return old_rule

	def get_events(self, start_time, end_time):
		"""
		Returns a list of event details that occurred in a given time interval.
		"""

		return [event.as_dict() for event in self._events if start_time <= event.time <= end_time]

	def get_total_bandwidth(self, start_time, end_time):
		return {t: b for t, b in self._total_bandwidth.iteritems() if start_time < t < end_time}

	def _handle_packet(self, event):
		"""
		Handles an incoming packet by checking if the current active rules
		set allow it to be forwarded on to the other connected network.
		If the packet is allowed to be forwarded, an forwarding rule is installed
		in the underlying SDN switch. Otherwise, a rule which ignores this flow is installed
		in the underlying SDN switch.
		"""

		# Ignore events that are related to other switches in the network.
		if event.dpid != self._firewall_dpid:
			return

		packet = event.parsed  # Packet is the original L2 packet sent by the switch
		packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

		if packet_in.in_port not in [self._incoming_port, self._outgoing_port]:
			self._log.warning('Received a packet from an unfamiliar port: %s' % packet_in.in_port)
			return

		# If we already installed a matching flow record for this type of packet
		# no need to reinstall one, simply forward this packet to the output port set in the flow rule.
		flow_record = self._switches[event.dpid].has_match(packet)
		if flow_record:
			self._switches[event.dpid].send_packet(packet_in.data, [flow_record.out_port], of.OFPP_NONE)
			return

		action = self._get_action_for_flow(packet, packet_in.in_port)
		if action == Action.Allowed:
			out_port = self._outgoing_port if packet_in.in_port == self._incoming_port else self._incoming_port
		else:
			# install rule in the switch that ignores that packet
			out_port = of.OFPP_NONE

		action = of.ofp_action_output(port=out_port)
		match = of.ofp_match.from_packet(packet, in_port=packet_in.in_port)
		self._switches[event.dpid].add_flow_mod(action, match, buffer_id=packet_in.buffer_id, idle_timeout=self._flow_active_time_secs)

	def _get_action_for_flow(self, packet, in_port):
		"""
		Decides and returns the action (allow/block) that should be taken on a given packet.
		"""

		if not isinstance(packet.next, ipv4) or not (isinstance(packet.next.next, tcp) or isinstance(packet.next.next, udp)):
			return Action.Allowed

		# Find the direction of the packet.
		if in_port == self._outgoing_port:
			direction = Direction.Incoming
		elif in_port == self._incoming_port:
			direction = Direction.Outgoing
		else:
			return Action.Blocked

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

		if self._mode == Mode.BlackList:
			has_match = filter(matches_packet, self._blacklist_rules) != []
			action = Action.Blocked if has_match else Action.Allowed

		elif self._mode == Mode.WhiteList:
			has_match = filter(matches_packet, self._whitelist_rules) != []
			action = Action.Allowed if has_match else Action.Blocked
		else:  # Passthrough mode
			action = Action.Allowed

		event = Event(
			direction=direction,
			src_ip=src_ip,
			dst_ip=dst_ip,
			protocol=protocol,
			src_port=src_port,
			dst_port=dst_port,
			action=action,
			time=time.time()
		)

		current_time = time.time()
		self._events.append(event)

		# Cleanup old events.
		self._events = [event for event in self._events if event.time > current_time - self._time_to_keep_stats_secs]
		self._dump_events()

		self._log.info(event)
		return action

	def _handle_ConnectionUp(self, event):
		"""
		Handles a ConnectionUp event by starting the flow stats retrieval timer.
		"""
		super(Firewall, self)._handle_ConnectionUp(event)

		# Ignore events that are related to other switches in the network.
		if event.dpid != self._firewall_dpid:
			return

		# Enable flow stats retrieval.
		self._switches[event.dpid].enable_flow_stats_retrieval(self._flow_starts_retrieval_interval_secs)

	def _handle_FlowStatsReceived(self, event):
		"""
		Handles the FlowStatsReceived event received from some switch by
		calculating the current utilization of each link connecting to this switch.
		"""

		super(Firewall, self)._handle_FlowStatsReceived(event)

		# Ignore events that are related to other switches in the network.
		if event.dpid != self._firewall_dpid:
			return

		total_bytes_added = 0.0
		for current_flow_stat in event.stats:
			dpid, out_port = event.dpid, current_flow_stat.actions[0].port
			if out_port == 65533:  # Ignore flows destined to the controller.
				continue

			# Calculate the flow's average throughput in the interval between the time
			# when the last flow stat was received from this switch and now.
			last_flow_stat = self._get_flow_stat(current_flow_stat.match)
			total_bytes_added += self._calc_added_bytes(last_flow_stat, current_flow_stat)

		current_bandwidth_mbit_sec = total_bytes_added * 8 / 1024 / 1024
		self._log.debug('Current bandwidth: %s Mbit/sec:' % current_bandwidth_mbit_sec)

		current_time = time.time()
		self._total_bandwidth[current_time] = current_bandwidth_mbit_sec

		# Cleanup old bandwidth statistics.
		self._total_bandwidth = {t: b for t, b in self._total_bandwidth.iteritems() if t > current_time - self._time_to_keep_stats_secs}
		self._active_flows = event.stats

	def _load_configuration(self):
		"""
		Loads the configuration from the configuration file.
		"""

		config = utils.load_yaml(self.CONFIG_FILE_PATH)
		self._incoming_port = config['physical_ports']['incoming']
		self._outgoing_port = config['physical_ports']['outgoing']
		self._mode = Mode(config['mode'])
		self._flow_active_time_secs = config['flow_active_time_secs']
		self._time_to_keep_stats_secs = config['time_to_keep_stats_secs']
		self._flow_starts_retrieval_interval_secs = config['flow_starts_retrieval_interval_secs']
		self._firewall_dpid = config['firewall_dpid']
		self._blacklist_rules = [Rule(**rule_dict) for rule_dict in config['blacklist_rules']]
		self._whitelist_rules = [Rule(**rule_dict) for rule_dict in config['whitelist_rules']]

	def _dump_configuration(self):
		"""
		Writes the active configuration to the configuration file.
		"""

		config = {
			'physical_ports': {
				'incoming': self._incoming_port,
				'outgoing': self._outgoing_port,
			},
			'mode': self._mode.name,
			'flow_active_time_secs': self._flow_active_time_secs,
			'time_to_keep_stats_secs': self._time_to_keep_stats_secs,
			'flow_starts_retrieval_interval_secs': self._flow_starts_retrieval_interval_secs,
			'firewall_dpid': self._firewall_dpid,
			'blacklist_rules': [rule.as_dict() for rule in self._blacklist_rules],
			'whitelist_rules': [rule.as_dict() for rule in self._whitelist_rules],
		}

		utils.dump_yaml(self.CONFIG_FILE_PATH, config)

	def _load_events(self):
		"""
		Loads all events from the events file.
		"""

		try:
			with open(self.EVENTS_FILE, 'r') as f:
				return pickle.loads(f.read())
		except:
			return []

	def _dump_events(self):
		"""
		Dumps all events to the events file.
		"""

		with open(self.EVENTS_FILE, 'w') as f:
			f.write(pickle.dumps(self._events))

	def _get_flow_stat(self, match):
		"""
		Finds and returns the latest flow statistics object as received
		from a given switch, which matches a given ofp_match object.
		"""

		for flow in self._active_flows:
			# If both ofp_match objects match each other, they represent the same flow.
			if flow.match.matches_with_wildcards(match) and match.matches_with_wildcards(flow.match):
				return flow

		return None

	@staticmethod
	def _calc_added_bytes(first_flow_stat, second_flow_stat):
		"""
		Calculates the average number of transferred bytes as
		reported in two different flow statistic objects.
		"""

		# Calculate the total duration of the flow by the second flow stat.
		second_duration = second_flow_stat.duration_sec + second_flow_stat.duration_nsec * 0.000000001
		second_byte_count = second_flow_stat.byte_count

		if first_flow_stat is None:
			first_duration = 0
			first_byte_count = 0
		else:
			# Calculate the total duration of the flow by the first flow stat.
			first_duration = first_flow_stat.duration_sec + first_flow_stat.duration_nsec * 0.000000001
			first_byte_count = first_flow_stat.byte_count

		# Calculate and return the average bytes count in the time interval between the two flow stats.
		byte_count_diff = second_byte_count - first_byte_count
		duration_diff = second_duration - first_duration
		return byte_count_diff / duration_diff if duration_diff != 0 else byte_count_diff

	@property
	def mode(self):
		"""
		Returns the firewall's current work mode.
		"""

		return self._mode

	@property
	def active_rules(self):
		"""
		Returns the set of current active rules.
		"""

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
	# Register instances of the specific DataCenterController and Discovery to POX's core.
	core.registerNew(Firewall)
	interface.FirewallInterface().start_serve_loop()

