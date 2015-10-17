import time
import xmlrpclib

from flask import (
	Flask,
	send_from_directory,
	make_response,
	jsonify,
	request
)

from flask.ext.login import (
	LoginManager,
	current_user,
	login_user,
	login_required,
	logout_user
)

import wtforms_json
import config

from models import User
from forms import LoginForm


PROTOCOLS_FILE = "protocols.txt"

# Create a Flask app.
app = Flask(__name__, static_folder='static')
app.debug = True
app.config.from_object('config')

# Init WTForms-JSON to allow populating WTForms from JSON content.
wtforms_json.init()

# Init the login manager and the admin user
login_manager = LoginManager()
login_manager.init_app(app)
admin = User("admin")

# Init the firewall instance
firewall = xmlrpclib.ServerProxy('http://127.0.0.1:9000')


def success(text, code=200, data=None):
	return make_response(jsonify(success=True, data=data or {}, status=text, code=code), code)


def fail(text, code=500, data=None):
	return make_response(jsonify(success=False, data=data or {}, status=text, code=code), code)


@app.errorhandler(404)
def not_found(error):
	return fail('resource not found', 404)


@app.errorhandler(405)
def not_found(error):
	return fail('method not allowed for this URL', 405)


@login_manager.unauthorized_handler
def unauthorized():
	return fail('you must be logged in order to access this resource!', 403)


@login_manager.user_loader
def load_user(userid):
	return admin


@app.route('/', methods=['GET'])
def index():
	"""
	Returns the index page of the CloudFirewall app.
	"""
	
	return send_from_directory(app.static_folder, 'index.html')


@app.route('/isAuthenticated', methods=['GET'])
def is_authenticated():
	"""
	Handles users login requests.
	"""
	if current_user.is_authenticated():
		return success('User logged in successfully', 200)

	return unauthorized()


@app.route('/login', methods=['POST'])
def login():
	"""
	Handles a user login request.
	"""
	
	if current_user.is_authenticated():
		return success('Admin logged in successfully', 200)

	# Validate client-side form data.
	form = LoginForm.from_json(request.json)
	if form.validate():
		# Login and validate the user.
		login_user(admin)
		admin.set_authenticated(True)
		return success('Admin logged in successfully', 200)

	return fail('Invalid username or password', 500)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
	"""
	Handles users logout requests.
	"""
	
	logout_user()
	admin.set_authenticated(False)
	return success('User logged out successfully', 200)


@app.route('/events', methods=['GET'])
@login_required
def get_events():
	"""
	Returns the firewall's events table by a certain time range.
	"""
	
	try:
		# TODO: move time to configuration or use dynamic times from the UI.
		current_time = time.time()
		events = firewall.get_events(current_time - config.FW_EVENTS_QUERY_INTERVAL_SECS, current_time)
		for event in events:
			event['time'] = time.ctime(event['time'])

		return success('Events table retrieved successfully', 200, events)

	except Exception, e:
		return fail('Could not retrieve events table. Error: %s' % e)


@app.route('/mode', methods=['GET'])
@login_required
def get_mode():
	"""
	Returns the current work-mode of the firewall.
	"""
	
	try:
		mode = firewall.get_mode()
		return success('Firewall mode retrieved successfully', 200, mode)

	except Exception, e:
		return fail('Could not retrieve firewall mode. Error: %s' % e)


@app.route('/mode', methods=['POST'])
@login_required
def set_mode():
	"""
	Sets the current work-mode of the firewall.
	"""

	try:
		mode = request.get_json()['mode']
		firewall.set_mode(mode)
		return success('Firewall mode changed successfully', 200, mode)

	except Exception, e:
		return fail('Could not change firewall mode. Error: %s' % e)


@app.route('/rules', methods=['GET'])
@login_required
def get_rules():
	"""
	Returns the firewall's current rules set.
	"""

	try:
		return success('Rules set retrieved successfully', 200, firewall.get_active_rules())

	except Exception, e:
		return fail('Could not retrieve firewall rules set. Error: %s' % e)


@app.route('/rules', methods=['POST'])
@login_required
def add_rule():
	"""
	Adds a new rule to the firewall's rule table.
	"""

	try:
		rule = request.get_json()
		direction = rule['direction']
		src_ip = rule['sourceIp']
		dst_ip = rule['destinationIp']
		protocol = rule['protocol']
		src_port = rule['sourcePort']
		dst_port = rule['destinationPort']

		firewall.add_rule(direction, src_ip, dst_ip, protocol, src_port, dst_port)
		return success('New rule added successfully', 200, rule)

	except Exception, e:
		return fail('Could not add rule to firewall. Error: %s' % e)


@app.route('/rules', methods=['PUT'])
@login_required
def edit_rule():
	"""
	Edits an existing rule in the firewall's rule table.
	"""

	try:
		rule = request.get_json()
		rule_number = int(rule['id']) - 1
		direction = rule['newDirection']
		src_ip = rule['newSourceIp']
		dst_ip = rule['newDestinationIp']
		protocol = rule['newProtocol']
		src_port = rule['newSourcePort']
		dst_port = rule['newDestinationPort']

		firewall.edit_rule(rule_number, direction, src_ip, dst_ip, protocol, src_port, dst_port)
		return success('Rule changed successfully', 200, rule)

	except Exception, e:
		return fail('Could not change rule. Error: %s' % e)


@app.route('/rules', methods=['DELETE'])
@login_required
def delete_rule():
	"""
	Deletes an existing rule from the firewall's rule table.
	"""

	try:
		rule_num = request.get_json()["id"] - 1
		deleted_rule = firewall.delete_rule(rule_num)
		return success('Rule deleted successfully', 200, deleted_rule)

	except Exception, e:
		return fail('Could not delete the rule from firewall. Error: %s' % e)


@app.route('/DataFlowStats', methods=['GET'])
@login_required
def get_fw_data_flow_stats():
	"""
	Returns events that occurred in the FW in the past few minutes (as stated in the config).
	"""

	try:
		current_time = time.time()
		data = firewall.get_total_bandwidth(current_time - config.FW_FLOW_DATA_QUERY_INTERVAL_SECS, current_time)
		labels = [time.ctime(float(t)).split()[3] if (int(float(t)) % 10 == 0) else ' ' for t in sorted(data.keys())]
		values = [v for k, v in sorted(data.iteritems())]

		line_chart_data = {
			"labels": labels,
			"datasets": {"data": values}
		}

		return success('Data flow stats table retrieved successfully', 200, line_chart_data)

	except Exception, e:
		print e
		return fail('Data flow stats table could not be retrived')


@app.route('/BlocksPerSessionByIntervalStats', methods=['GET'])
@login_required
def get_blocks_per_session_by_interval():
	"""
	Returns the total number of blocked sessions and allowed
	sessions in the past few minutes (as stated in the config).
	"""

	try:
		minutes = config.FW_BLOCKS_AND_ALLOWS_QUERY_INTERVAL_MINS
		bar_chart_data = {
			'labels': ['%s mins ago' % x for x in (m for m in xrange(minutes, 0, -1))],
			'datasets': {
				'sessions': [0] * minutes,
				'blocks': [0] * minutes,
			}
		}

		current_time = time.time()
		query_start_time = current_time - minutes * 60
		events = firewall.get_events(query_start_time, current_time)

		for event in events:
			event_time_mins = int(event['time']) / 60
			time_interval = event_time_mins - (int(query_start_time) / 60) - 1

			if event['action'] == 'Blocked':
				bar_chart_data['datasets']['blocks'][time_interval] += 1
			else:
				bar_chart_data['datasets']['sessions'][time_interval] += 1

		return success('Blocks and allows stats retrieved successfully', 200, bar_chart_data)

	except Exception, e:
		return fail('Could not retrieve stats. Error: %s' % e)


@app.route('/ProtocolStats', methods=['GET'])
@login_required
def get_sessions_per_protocol():
	try:
		pie_chart_data = {}

		current_time = time.time()
		for event in firewall.get_events(current_time - config.FW_SESSIONS_PER_PROTOCOL_QUERY_INTERVAL_SECS, current_time):
			dst_port = event["dst_port"]
			if dst_port in PROTOCOLS_BY_PORT:
				protocol = PROTOCOLS_BY_PORT[dst_port] + " (%s)" % dst_port
			else:
				protocol = str(dst_port)

			pie_chart_data.setdefault(protocol, 1)
			pie_chart_data[protocol] += 1

		return success('Sessions per protocol stats retrieved successfully', 200, pie_chart_data)

	except Exception, e:
		return fail('Could not retrieve stats. Error: %s' % e)


def read_protocols():
	"""
	Reads the protocols file and creates a mapping
	between a port number and a protocol name.
	:return:
	"""

	protocols = {}
	with open(PROTOCOLS_FILE, 'r') as f:
		for line in f.readlines():
			fields = line.split('\t')
			prot_no = int(fields[0].strip())
			proto_name = fields[1].strip()
			proto_desc = fields[2].strip()
			protocols[prot_no] = proto_name

	return protocols

PROTOCOLS_BY_PORT = read_protocols()

if __name__ == '__main__':
	app.run(host='')
