import time

from pox.core import core
from pox.lib import recoco
from pox.openflow import libopenflow_01 as of


class FlowRecord:
	"""
	Represents a flow record of an SDN switch
	"""

	def __init__(self, **kwargs):
		self.match = None
		self.out_port = None
		self.idle_timeout = None
		self.creation_time = time.time()

		self.__dict__.update((k, v) for k, v in kwargs.iteritems() if hasattr(self, k))

	def __str__(self):
		return 'FlowRecord (%s)' % ', '.join('%s=%s' % (k, v) for k, v in zip(self.keys_string_list(), self.values_string_list()))

	def __repr__(self):
		return self.__str__()

	@staticmethod
	def keys_string_list():
		return [
			'in_port',
			'dl_src',
			'dl_dst',
			'dl_vlan',
			'dl_vlan_pcp',
			'dl_type',
			'nw_tos',
			'nw_proto',
			'nw_src',
			'nw_dst',
			'tp_src',
			'tp_dst',

			'out_port',
			'idle_timeout',
			'creation_time',
		]

	def values_string_list(self):
		return [
			str(self.match.in_port),
			str(self.match.dl_src),
			str(self.match.dl_dst),
			str(self.match.dl_vlan),
			str(self.match.dl_vlan_pcp),
			str(self.match.dl_type),
			str(self.match.nw_tos),
			str(self.match.nw_proto),
			str(self.match.nw_src),
			str(self.match.nw_dst),
			str(self.match.tp_src),
			str(self.match.tp_dst),

			str(self.out_port),
			str(self.idle_timeout),
			str(self.creation_time),
		]


class OpenFlowSwitch(object):
	"""
	This class implements basic communication functionality with an SDN switch.
	"""

	def __init__(self, connection_up_event):
		if not hasattr(self, '_log'):
			self._log = core.getLogger('OpenFlowSwitch %s' % connection_up_event.dpid)

		self._dpid = connection_up_event.dpid
		self._connection = connection_up_event.connection
		self._ports = connection_up_event.ofp.ports  # Save the list of physical ports of the switch.
		self._flow_table = []  # Initialize the inner flow table for the learning switch.
		self._stats_req_timer = None

	@property
	def dpid(self):
		"""
		The DPID of this switch.
		"""

		return self._dpid

	@property
	def flow_table(self):
		"""
		The current flow table this switch holds.
		"""

		return self._flow_table

	@property
	def ports(self):
		"""
		The list of physical ports this switch has.
		"""

		return [port.port_no for port in self._ports]

	def add_flow_mod(self, action, match, buffer_id=-1, raw_data=None, idle_timeout=0):
		"""
		Sends a flow modification record to the switch
		"""

		self._log.debug('Adding new flow record, out_port = %s, idle_timeout = %s, match: \n%s' % (action.port, idle_timeout, match.show()))
		fm = of.ofp_flow_mod(command=of.OFPFC_ADD, match=match, action=action, idle_timeout=idle_timeout)
		fm.flags |= of.OFPFF_SEND_FLOW_REM  # Force the switch to notify the controller when flow records are removed.

		# It is not mandatory to set fm.data or fm.buffer_id
		if buffer_id is not None and buffer_id != -1:
			# Valid buffer ID was sent from switch, we do not need to encapsulate raw data in response
			fm.buffer_id = buffer_id

		elif raw_data is not None:
			# No valid buffer ID was sent but raw data exists, send raw data with flow_mod
			fm.data = raw_data

		# Send message to switch
		self._connection.send(fm)

		# Add the new flow record to our inner flow records table.
		self._flow_table.append(FlowRecord(match=match, out_port=action.port, idle_timeout=idle_timeout))

		self._log_flow_table()

	def remove_flow_mod(self, **kwargs):
		"""
		Sends a flow record removal command to the switch.
		"""

		self._log.debug('Removing flow record: %s' % kwargs)
		match = of.ofp_match(**kwargs)  # Create an ofp_match from the given keyword arguments.
		fm = of.ofp_flow_mod(command=of.OFPFC_DELETE, match=match)
		self._connection.send(fm)  # Send flow-mod message
		self.remove_flows_from_internal_flow_table(match)

	def remove_flows_from_internal_flow_table(self, match):
		"""
		Removes all FlowRecord instances from the internal
		flow table that matches a given ofp_match.
		"""

		# Find all affected flow record in the switch's internal flow records table.
		flow_records_to_remove = [fr for fr in self._flow_table if match.matches_with_wildcards(fr.match)]

		if flow_records_to_remove:
			# Remove all affected flow records and write the new table to the log.
			for fr in flow_records_to_remove:
				self._flow_table.remove(fr)
			self._log_flow_table()

	def send_packet(self, raw_data, out_ports, in_port):
		"""
		Sends a packet out of the specified switch port.
		If buffer_id is a valid buffer on the switch, use that. Otherwise,
		send the raw data in raw_data.
		The "in_port" is the port number that packet arrived on. Use
		OFPP_NONE if you're generating this packet.
		"""

		# We tell the switch to take the packet with id buffer_if from in_port
		# and send it to out_port.
		# If the switch did not specify a buffer_id, it must have specified
		# the raw data of the packet, so in this case we tell it to send the raw data
		actions = [of.ofp_action_output(port=out_port) for out_port in out_ports]
		msg = of.ofp_packet_out(in_port=in_port, actions=actions)
		msg.data = raw_data

		# Send message to switch
		self._connection.send(msg)

	def has_match(self, packet):
		"""
		Returns True if the switch has a matching flow
		record for a given packet, or False otherwise.
		"""

		match = of.ofp_match.from_packet(packet)
		for fr in self._flow_table:
			if fr.match.matches_with_wildcards(match):
				return fr

		return False

	def enable_flow_stats_retrieval(self, interval_secs):
		"""
		Starts a timer that periodically requests the switch to send flow statistics.
		The reply will be received through a FlowStatsReceived event.
		"""

		self._stats_req_timer = recoco.Timer(interval_secs, lambda: self._connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request())), recurring=True)

	def disable_flow_stats_retrieval(self):
		"""
		Stops the timer that periodically requests the switch to send flow statistics.
		"""

		self._stats_req_timer.cancel()
		self._stats_req_timer = None

	def _log_flow_table(self):
		"""
		Logs the current flow table of the switch
		"""

		try:
			from terminaltables import AsciiTable
			titles = FlowRecord.keys_string_list()
			rows = [fr.values_string_list() for fr in self._flow_table]
			if rows:
				table = AsciiTable([titles] + rows).table
			else:
				table = '*EMPTY*'
			self._log.debug('Flow table:\n%s' % table)
		except Exception, e:
			self._log.exception(e)


class OpenFlowController(object):
	"""
	This abstract class is used as a base class for a concrete OpenFlow controller.
	This class implements basic and common functionality of an OpenFlow controller.
	"""

	def __init__(self):
		self._log = core.getLogger(self.__class__.__name__)
		core.openflow.addListeners(self)  # Register this instance to handle OpenFlow events.
		self._switches = {}  # Maps between a DPID and its matching OpenFlowSwitch instance.

	def _handle_ConnectionUp(self, event):
		"""
		Handles a new switch connection up event by creating a new,
		OpenFlowSwitch instance and saving it in the local switches map.
		"""

		self._log.debug('Switch %s connected!' % event.dpid)
		self._switches[event.dpid] = OpenFlowSwitch(event)

	def _handle_ConnectionDown(self, event):
		"""
		Handles a new switch connection down event by removing the relevant
		OpenFlowSwitch instance from the local switches map.
		"""

		self._log.info('Switch %s disconnected!' % event.dpid)
		del self._switches[event.dpid]

	def _handle_PacketIn(self, event):
		"""
		Handles packet in messages from the switch.
		"""

		packet = event.parsed  # Packet is the original L2 packet sent by the switch.

		# Ignore incomplete packets.
		if not packet.parsed:
			self._log.warning("Ignoring incomplete packet")
			return

		# Ignore IPv6 discovery messages:
		if str(packet.dst).startswith('33:33:'):
			return

		self._handle_packet(event)

	def _handle_PortStatus(self, event):
		"""
		Handles a link change event by removing invalid flow rules.
		"""

		self._log.debug('Handling port status event')

		if event.ofp.desc.config == 0:
			return

		# Get the relevant switch instance.
		switch = self._switches[event.dpid]

		flow_records_to_remove = [fr for fr in switch.flow_table if fr.out_port == event.port]
		for fr in flow_records_to_remove:
			switch.remove_flow_mod(in_port=fr.match.in_port, dl_src=fr.match.dl_src, dl_dst=fr.match.dl_dst)

	def _handle_FlowRemoved(self, event):
		"""
		Handles a flow removal event by removing deprecated FlowRecord
		instances from the switch's internal flow table.
		"""

		# Handles the case where the controller was restarted
		# and all active switches now remove their flow records.
		if event.dpid not in self._switches:
			return

		self._log.debug('Flow removed: %s' % event.ofp.match.show())
		self._switches[event.dpid].remove_flows_from_internal_flow_table(event.ofp.match)

	def _handle_ErrorIn(self, event):
		"""
		Handles an ErrorIn event by logging the error.
		"""

		self._log.error('Error: %s' % event)

	def _handle_FlowStatsReceived(self, event):
		"""
		Handles flow statistics event.
		"""

		pass

	def _handle_packet(self, event):
		"""
		Handles a PacketIn event received from some switch.
		This abstract method is left for the inheriting class to implement.
		"""

		raise NotImplementedError
