from cmd import Cmd
from urlparse import urljoin

import requests


class CloudFirewallAPI(object):

	def __init__(self, urlbase, verbose=False):
		self._urlbase = urlbase
		self._verbose = verbose
		self._cookies = {}

	def login(self, username, password):
		"""
		Login a user to the server.
		"""

		url = urljoin(self._urlbase, '/login')
		data = {
			'username': username,
			'password': password
		}
		r = requests.post(url, json=data)
		self._cookies = r.cookies
		if self._verbose:
			print 'REQUEST: \n URL: %s\n Method: %s\n Body: %s' % (r.request.url, r.request.method, r.request.body)
			print 'RESPONSE: \n Status: %s \n Body: %s\n' % (r.status_code, r.content)

	def logout(self):
		"""
		Logout a user from the server.
		"""

		url = urljoin(self._urlbase, '/logout')
		data = {}
		r = requests.post(url, json=data, cookies=self._cookies)
		self._cookies = r.cookies
		if self._verbose:
			self._log_response_data(r)

	def get_events(self):
		"""
		Gets the latest list of events that occurred in the firewall
		"""

		url = urljoin(self._urlbase, '/events')
		data = {}
		r = requests.get(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def get_mode(self):
		"""
		Gets the firewall's current work mode.
		"""

		url = urljoin(self._urlbase, '/mode')
		data = {}
		r = requests.get(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def set_mode(self, mode):
		"""
		Changes the firewall's current work mode.
		"""

		url = urljoin(self._urlbase, '/mode')
		data = {
			'mode': mode,
		}
		r = requests.post(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def get_rules(self):
		"""
		Gets the firewall's active rules set.
		"""

		url = urljoin(self._urlbase, '/rules')
		data = {}
		r = requests.get(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def add_rule(self, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		"""
		Adds a new rule to the firewall's active rules set.
		"""

		url = urljoin(self._urlbase, '/rules')
		data = {
			'direction': direction,
			'sourceIp': src_ip,
			'destinationIp': dst_ip,
			'protocol': protocol,
			'sourcePort': src_port,
			'destinationPort': dst_port
		}
		r = requests.post(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def edit_rule(self, rule_id, direction, src_ip, dst_ip, protocol, src_port, dst_port):
		"""
		Delete an existing rule from the firewall's active rules set..
		"""

		url = urljoin(self._urlbase, '/rules')
		data = {
			'id': rule_id,
			'newDirection': direction,
			'newSourceIp': src_ip,
			'newDestinationIp': dst_ip,
			'newProtocol': protocol,
			'newSourcePort': src_port,
			'newDestinationPort': dst_port
		}
		r = requests.put(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	def delete_rule(self, rule_id):
		"""
		Delete an existing rule from the firewall's active rules set.
		"""

		url = urljoin(self._urlbase, '/rules')
		data = {
			'id': rule_id
		}
		r = requests.delete(url, json=data, cookies=self._cookies)
		if self._verbose:
			self._log_response_data(r)

	@staticmethod
	def _log_response_data(response, is_req_binary=False, is_res_binary=False):
		"""
		Logs response data to stdout.
		"""

		print 'REQUEST: \n URL: %s\n Method: %s\n Body: %s' % (response.request.url, response.request.method, '*Binary*' if is_req_binary else response.request.body)
		print 'RESPONSE: \n Status: %s \n Body: %s\n' % (response.status_code, '*Binary*' if is_res_binary else response.content)


class CloudFirewallAPITester(Cmd):
	"""
	Simple interactive CLI to test CloudFirewall's RESTful API.
	"""

	def __init__(self):
		Cmd.__init__(self)
		self._api = CloudFirewallAPI('http://localhost:5000', True)

	def do_set_urlbase(self, url_base):
		self._api = CloudFirewallAPI(url_base, True)
		print 'OK'

	def do_login(self, line):
		"""
		Login a user to the server.
		Parameters: <username> <password>
		"""

		email, password = line.split()
		self._api.login(email, password)

	def do_logout(self, line):
		"""
		Logout the current user from the server.
		Parameters: None.
		"""

		self._api.logout()

	def do_get_events(self, line):
		"""
		Gets the latest list of events that occurred in the firewall.
		Parameters: None.
		"""

		self._api.get_events()

	def do_get_mode(self, line):
		"""
		Gets the firewall's current work mode.
		Parameters: None
		"""

		self._api.get_mode()

	def do_set_mode(self, line):
		"""
		Set's the firewall's current work mode.
		Parameters: <new mode>
		where: new mode is one of ['PassThrough', 'WhiteList', 'BlackList'].
		"""

		new_mode = line
		self._api.set_mode(new_mode)

	def do_get_rules(self, line):
		"""
		Gets the firewall's current rules set.
		Parameters: None
		"""

		self._api.get_rules()

	def do_add_rule(self, line):
		"""
		Adds a new rule to the firewall's active rules set.
		Parameters: <direction> <src_ip> <dst_ip> <protocol> <src_port> <dst_port>
		"""

		direction, src_ip, dst_ip, protocol, src_port, dst_port = line.split()
		self._api.add_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)

	def do_edit_rule(self, line):
		"""
		Edits an existing rule from the firewall's active rules set.
		Parameters: <rule id> <direction> <src_ip> <dst_ip> <protocol> <src_port> <dst_port>
		"""

		rule_id, direction, src_ip, dst_ip, protocol, src_port, dst_port = line.split()
		rule_id = int(rule_id)
		self._api.edit_rule(rule_id, direction, src_ip, dst_ip, protocol, src_port, dst_port)

	def do_delete_rule(self, line):
		"""
		Deletes an existing rule from the firewall's active rules set.
		Parameters: <rule id>
		"""

		rule_id = int(line)
		self._api.delete_rule(rule_id)


if __name__ == '__main__':
	CloudFirewallAPITester().cmdloop()
