from enum import Enum
import json
import datetime
# from firewall_controller.of_base import OpenFlowController

class Mode(Enum):
    WhiteList = 1
    BlackList = 2
    PassThrough = 3

class State(Enum):
    ON = 1
    OFF = 2

class Protocol(Enum):
    HTTP = 1
    TCP = 2
    UDP = 3

class Firewall(): # TODO: inherint from OpenFlowController

    def __init__(self):
        self.configuration = self.read_configuration()

        self.mode = Firewall.string_to_mode(self.configuration['mode'])
        self.state = Firewall.boolean_to_state(self.configuration['state'])
        self.supported_protocols = self.parse_supported_protocols(self.configuration['protocols'])
        self.rules = self.configuration['rules']

        # self.add_event({"direction": "incoming", "type": "Block", "sourceIp": "255.255.255.255", "sourcePort": "3",
        #                 "destinationIp": "255.255.255.255", "destinationPort": "5", "country": "israel", "protocol": "TCP"})

    def read_configuration(self):
        return json.loads(open("configuration.json").read()) #TODO: read file name from user input

    def write_configuration(self):
        self.configuration['state'] = Firewall.state_to_boolean(self.state)
        self.configuration['mode'] = Firewall.mode_to_string(self.mode)
        self.configuration['rules'] = self.rules
        json.dump(self.configuration, open("configuration.json", 'w'))

    def parse_supported_protocols(self, protocols):
        result = []
        for protocol in protocols:
            result.append(Firewall.string_to_protocol(protocol))
        return result

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

    def get_mode(self):
        return self.mode

    def get_state(self):
        return self.state

    def get_rules(self):
        return self.rules

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

    def delete_rule(self, rule):
        rule_to_delete = self.find_rule(rule)
        if rule_to_delete is not None:
            self.rules.remove(rule_to_delete)
            self.write_configuration()
            return True
            # TODO: update all the switch tables
        else:
            return False

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

    def set_state(self, state):
        # TODO: if OFF then set to PASSTHROUGH mode
        self.state = state
        self.write_configuration()

    def set_mode(self, mode):
        # TODO: delete\edit all the rules in the switches
        self.mode = mode
        self.write_configuration()

    def get_supported_protocols(self):
        return self.supported_protocols

    #rules and working mode will be configured in JSON\YAML file
    def _handle_packet(self, event):
        #check if flow is confirmed in the rules table according to working mode

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch
        flow = {"direction": self.get_direction_by_port(packet_in.in_port), "sourceIp": [packet.payload.srcip],
                "sourcePort": packet.tp_src, "destinationIp": packet.payload.dstip,
                "destinationPort": packet.tp_dst, "protocol": packet.next.protocol}

        if(self.is_flow_confirmed(flow)):
            #install in the relevant port at the switch the relevant rule
            pass
        else:
            #install rule in the switch that ignores that packet
            pass

        self.log_event() #write to log the event details (packet and action)

    def is_flow_confirmed(self, flow):
        rule = self.find_rule(flow)
        if rule is not None and self.mode == Mode.WhiteList or \
            rule is None and self.mode == Mode.BlackList or \
            self.mode == Mode.PassThrough:
            return True
        else:
            return False

    def get_direction_by_port(self, port):
        return self.configuration["ports_to_direction"][str(port)]

    def add_event(self, event):
        timestamp = datetime.datetime.now().strftime("%d\%m\%Y %H:%M:%S")
        events_log = open('events.log','a')
        events_log.write(("{time} {direction} {type} {sourceIp} {sourcePort} {destinationIp} {destinationPort} {country} {protocol} \n").format(time=timestamp,
                    direction=event["direction"], type=event["type"], sourceIp=event["sourceIp"], sourcePort=event["sourcePort"],
                    destinationIp=event["destinationIp"], destinationPort=event["destinationPort"], country=event["country"],
                    protocol=event["protocol"]))
        events_log.close()

    @staticmethod
    def protocol_to_string(protocol):
        return{
            Protocol.HTTP: "HTTP",
            Protocol.TCP: "TCP",
            Protocol.UDP: "UDP"
        }[protocol]

    @staticmethod
    def string_to_protocol(protocol):
        return{
            "HTTP": Protocol.HTTP,
            "TCP": Protocol.TCP,
            "UDP": Protocol.UDP
        }[protocol]

    @staticmethod
    def mode_to_string(mode):
        return {
		Mode.WhiteList: "WhiteList",
		Mode.BlackList: "BlackList",
		Mode.PassThrough: "PassThrough",
	}[mode]

    @staticmethod
    def string_to_mode(mode):
        return {
		"WhiteList": Mode.WhiteList,
		"BlackList": Mode.BlackList,
		"PassThrough": Mode.PassThrough,
	}[mode]

    @staticmethod
    def state_to_boolean(state):
        return {
            State.OFF: False,
            State.ON: True
        }[state]

    @staticmethod
    def boolean_to_state(state):
        return {
            False: State.OFF,
            True: State.ON
        }[state]

if __name__ == '__main__':
    pass
