from enum import Enum
import json
import datetime
import Pyro4

import ipc

def get_proxy():
	return ipc.get_proxy_by_name('firewall')


class FirewallInterface(object): # TODO: inherint from OpenFlowController
	def __init__(self):
		pass

	@Pyro4.expose()
	def get_events(self):
		events_list = []

		with open("events.log") as events: # TODO: change file name to constant
			events = events.readlines()
		for line in events:
			data = line.rstrip().split(' ')
			event = {"time": data[0] + " " + data[1], "direction": data[2], "type": data[3], "sourceIp": data[4],
					 "sourcePort": data[5], "destinationIp": data[6], "destinationPort": data[7], "country": data[8],
					 "protocol": data[9]}
			events_list.append(event)

		return events_list

	@Pyro4.expose()
	def get_mode(self):
		return self.mode

	@Pyro4.expose()
	def get_state(self):
		return self.state

	@Pyro4.expose()
	def get_rules(self):
		return self.rules

	@Pyro4.expose()
	def add_rule(self, direction, source_ip, source_port, destination_ip, destination_port, protocol):
		rule = {"direction": direction, "sourceIp": source_ip, "sourcePort": source_port, "destinationIp": destination_ip,
				"destinationPort": destination_port, "protocol": protocol}
		if (self.find_rule(rule) is None):
			self.rules.append(rule)
			self.write_configuration()
			# TODO: update all the switch tables
			return True
		else:
			return False

	@Pyro4.expose()
	def delete_rule(self, rule):
		rule_to_delete = self.find_rule(rule)
		if rule_to_delete is not None:
			self.rules.remove(rule_to_delete)
			self.write_configuration()
			return True
			# TODO: update all the switch tables
		else:
			return False

	@Pyro4.expose()
	def edit_rule(self, old_rule, new_rule ): # TODO: test
		rule_to_edit = self.find_rule(old_rule)
		if rule_to_edit is not None:
				rule_to_edit["direction"] = new_rule["direction"]
				rule_to_edit["sourceIp"] = new_rule["sourceIp"]
				rule_to_edit["sourcePort"] = new_rule["sourcePort"]
				rule_to_edit["destinationIp"] = new_rule["destinationIp"]
				rule_to_edit["destinationPort"] = new_rule["destinationPort"]
				rule_to_edit["protocol"] = new_rule["protocol"]
				self.write_configuration()
				# TODO: update all the switch tables
		else:
			raise Exception("Rule not found")

	@Pyro4.expose()
	def find_rule(self, rule):
		for current_rule in self.rules:
			if current_rule["direction"] == rule["direction"] and \
				current_rule["sourceIp"] == rule["sourceIp"] and \
				current_rule["sourcePort"] == rule["sourcePort"] and \
				current_rule["destinationIp"] == rule["destinationIp"] and \
				current_rule["destinationPort"] == rule["destinationPort"] and \
				current_rule["protocol"] == rule["protocol"]:
					return current_rule
		return None

	@Pyro4.expose()
	def set_state(self, state):
		# TODO: if OFF then set to PASSTHROUGH mode
		self.state = state
		self.write_configuration()

	@Pyro4.expose()
	def set_mode(self, mode):
		# TODO: delete\edit all the rules in the switches
		self.mode = mode
		self.write_configuration()

	@Pyro4.expose()
	def get_supported_protocols(self):
		return self.supported_protocols

	@Pyro4.expose()
	def add_event(self, event):
		timestamp = datetime.datetime.now().strftime("%d\%m\%Y %H:%M:%S")
		events_log = open('events.log','a')
		events_log.write(("{time} {direction} {type} {sourceIp} {sourcePort} {destinationIp} {destinationPort} {country} {protocol} \n").format(time=timestamp,
					direction=event["direction"], type=event["type"], sourceIp=event["sourceIp"], sourcePort=event["sourcePort"],
					destinationIp=event["destinationIp"], destinationPort=event["destinationPort"], country=event["country"],
					protocol=event["protocol"]))
		events_log.close()




