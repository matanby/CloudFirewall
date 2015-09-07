from flask import Flask, send_from_directory, make_response, jsonify, request
from flask.ext.login import LoginManager, current_user, login_user, login_required, logout_user
# from flask.ext.sqlalchemy import SQLAlchemy
from models import User
from forms import LoginForm
from firewall import Firewall
from flask.ext.socketio import SocketIO

import wtforms_json
import json
import datetime

BLOCK_EVENT_TYPE = "block"

EVENT_TIME = "time"

BLOCKS = "blocks"

EVENT_TYPE = "type"

SESSIONS = "sessions"

DATASETS = "datasets"

app = Flask(__name__, static_folder='static')
app.debug = True
app.config.from_object('config')
# db = SQLAlchemy(app)

# Init WTForms-JSON to allow populating WTForms from JSON content.
wtforms_json.init()

# Init web sockets framework
socketio = SocketIO(app)

# Init the login manager and the admin user
login_manager = LoginManager()
login_manager.init_app(app)
admin = User("admin")

# Init the firewall instance
firewall = Firewall()


def success(text, code=200, data=None):
	return make_response(jsonify(success=True, data=data or {}, status=text, code=code), code)

def fail(text, code=500, data=None):
	return make_response(jsonify(success=False, data=data or {}, status=text, code=code), code)

@app.errorhandler(404)
def not_found(error):
	return fail('resource not found', 404)

@app.errorhandler(405)
def not_found(error):
	return fail('method not allowed for this route', 405)

@login_manager.unauthorized_handler
def unauthorized():
	return fail('you must be logged in to access this resource!', 403)

@login_manager.user_loader
def load_user(userid):
	return admin


@app.route('/', methods=['GET'])
def index():
	"""
	Returns the index page of the CloudGallery cloudfirewall.
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
	Handles users login requests.
	"""
	if current_user.is_authenticated():
		return success('User logged in successfully', 200)

	# validate client-side form data.
	form = LoginForm.from_json(request.json)
	if form.validate():
		# Login and validate the user.
		login_user(admin)
		admin.set_authneticated(True)
		events_updater()
		return success('User logged in successfully', 200)

	return fail('Invalid username or password', 500)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
	"""
	Handles users logout requests.
	"""
	logout_user()
	admin.set_authneticated(False)
	return success('User logged out successfully', 200)

@app.route('/events', methods=['GET'])
@login_required
def events_table():
	"""

	"""
	try:
		return success('Events table retrieved succesfuly', 200, firewall.get_events())
	except:
		return fail('Could not retrieve events table')

@app.route('/mode', methods=['GET'])
@login_required
def get_mode():
	"""

	"""
	try:
		mode = Firewall.mode_to_string(firewall.get_mode())
		return success('Firewall Mode retrieved succesfuly', 200, mode)
	except:
		return fail('Could not retrieve firewall mode')

@app.route('/mode', methods=['POST'])
@login_required
def set_mode():
	"""

	"""
	try:
		mode = request.get_json()['mode']
		firewall.set_mode(Firewall.string_to_mode(mode))
		return success('Firewall Mode retrieved succesfuly', 200, mode)
	except:
		return fail('Could not change firewall mode')

@app.route('/state', methods=['GET'])
@login_required
def get_state():
	"""

	"""
	try:
		state = json.dumps(Firewall.state_to_boolean(firewall.get_state()))
		return success('Firewall state retrieved succesfuly', 200, state)
	except:
		return fail('Could not retrieve firewall state')

@app.route('/state', methods=['POST'])
@login_required
def set_state():
	"""

	"""
	try:
		state = request.get_json()['state']
		firewall.set_state(Firewall.boolean_to_state(state))
		return success('Firewall state retrieved succesfuly', 200)
	except:
		return fail('Could not change firewall state')


@app.route('/rules', methods=['GET'])
@login_required
def rules_table():
	"""

	"""
	try:
		return success('Rules table retrieved succesfuly', 200, firewall.get_rules())
	except:
		return fail('Could not retrieve firewall rules table')

@app.route('/rules', methods=['POST'])
@login_required
def add_rule():
	rule = request.get_json()
	if(firewall.add_rule(rule['direction'], rule['sourceIp'], rule['sourcePort'],
						 rule['destinationIp'], rule['destinationPort'], rule['protocol'])):
		return success('New Rule added succesfuly', 200, rule)
	else:
		return fail('Cannot add rule to firewall')

@app.route('/rules', methods=['PUT'])
@login_required
def edit_rule():
	rule = request.get_json()
	old_rule = {"direction": rule['oldDirection'], "sourceIp": rule['oldSourceIp'], "sourcePort": rule['oldSourcePort'],
				"destinationIp": rule['oldDestinationIp'], "destinationPort": rule['oldDestinationPort'], "protocol": rule['oldProtocol']}
	new_rule = {"direction": rule['newDirection'], "sourceIp": rule['newSourceIp'], "sourcePort": rule['newSourcePort'],
				"destinationIp": rule['newDestinationIp'], "destinationPort": rule['newDestinationPort'], "protocol": rule['newProtocol']}
	try:
		firewall.edit_rule(old_rule, new_rule)
		return success('Rule data changed successfully', 200, rule)
	except:
		return fail('Could not edit rule')

@app.route('/protocols', methods=['GET'])
@login_required
def get_protocols():
	protocols = []
	for protocol in firewall.get_supported_protocols():
		protocols.append(Firewall.protocol_to_string(protocol))

	return success('Protocols list retrieved succesfuly', 200, protocols)

@app.route('/rules', methods=['DELETE'])
@login_required
def delete_rule():
	rule = request.get_json()
	if(firewall.delete_rule(rule)):
		return success('Rule deleted succesfuly', 200, rule)
	else:
		return fail('Could not delete the rule from firewall')

@socketio.on('get_events')
def handle_message():
	print "user connected to get events socket"

def events_updater():
	import threading
	threading.Timer(50000.0, events_updater).start()
	current_events = firewall.get_events()
	socketio.emit('event_occured', firewall.get_events())
	print "data sent."

@app.route('/BlocksAndAllowsStats', methods=['GET'])
@login_required
def get_blocks_and_allows_stats():
	# TODO: get data from firewall
	lineChartData = {
		"labels": ["", "", "", "", "", "", "", "", "", "", "", ""],
		"datasets": {
			"allows": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
			"blocks": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		}
    };

	for event in firewall.get_events():
		month = int(event["time"].split(" ")[0].split("\\")[1]) - 1 # Parse the month number out of the event log string
		type = event["type"]
		if type == "Allow":
			lineChartData["datasets"]["allows"][month] += 1
		elif type == "Block":
			lineChartData["datasets"]["blocks"][month] += 1

	return success('Stats table retrieved succesfuly', 200, lineChartData)

	# TODO: return failure in the relveant cases

@app.route('/BlocksPerSessionByIntervalStats', methods=['GET'])
@login_required
def get_blocks_per_session_by_interval():
	try:
		barChartData = {
			"labels": ["10 mins ago", "9 mins ago", "8 mins ago", "7 mins ago", "6 mins ago", "5 mins ago",
					   "4 mins ago", "3 mins ago", "2 mins ago", "1 mins ago"],
			DATASETS: {
				SESSIONS: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				BLOCKS: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
			}
		};

		last_10_mins_events = [event for event in firewall.get_events() if is_in_time_interval(event["time"], 10)]

		for event in last_10_mins_events:
			event_time_mins = int(event["time"].split(" ")[1].split(":")[1])
			barChartData[DATASETS][SESSIONS][event_time_mins] +=1

			if is_in_time_interval(event[EVENT_TIME], 10, 9):
				barChartData[DATASETS][SESSIONS][0] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][0] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 9, 8)):
				barChartData[DATASETS][SESSIONS][1] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][1] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 8, 7)):
				barChartData[DATASETS][SESSIONS][2] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][2] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 7, 6)):
				barChartData[DATASETS][SESSIONS][3] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][3] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 6, 5)):
				barChartData[DATASETS][SESSIONS][4] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][4] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 5, 4)):
				barChartData[DATASETS][SESSIONS][5] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][5] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 4, 3)):
				barChartData[DATASETS][SESSIONS][6] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][6] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 3, 2)):
				barChartData[DATASETS][SESSIONS][7] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][7] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 2, 1)):
				barChartData[DATASETS][SESSIONS][8] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][8] += 1
			elif (is_in_time_interval(event[EVENT_TIME], 1, 0)):
				barChartData[DATASETS][SESSIONS][9] += 1
				if event[EVENT_TYPE] == BLOCK_EVENT_TYPE:
					barChartData[DATASETS][BLOCKS][9] += 1

		return success('Stats table retrieved succesfuly', 200, barChartData)

	except:
		return fail('Could not retrieve blocks per session by interval stats')

@app.route('/ProtocolStats', methods=['GET'])
@login_required
def get_blocks_per_protocol():

	try:
		pieChartData = {
			"HTTP": 0,
			"TCP": 0,
			"UDP": 0
		};

		for event in firewall.get_events():
			if (is_in_time_interval(event["time"], 5)):
				pieChartData[event["protocol"]] += 1

		return success('Stats table retrieved successfully', 200, pieChartData)
	except:
		return fail('Could not retrieve protocol stats')

@app.route('/SessionsPerDirectionStats', methods=['GET'])
@login_required
def get_sessions_per_direction():

	try:
		pieChartData = {
			"incoming": 0,
			"outgoing": 0
		};

		for event in firewall.get_events():
			if (is_in_time_interval(event["time"], 5)):
				pieChartData[event["direction"]] += 1

		return success('Stats table retrieved successfully', 200, pieChartData)

	except:
		return fail('Could not retrieve sessions per direction stats')


def is_in_time_interval(check_time_str, interval):
	time_interval = datetime.datetime.now() - datetime.timedelta(minutes=interval)
	check_time = datetime.datetime.strptime(check_time_str, "%d\%m\%Y %H:%M:%S")
	return (check_time > time_interval and check_time < time_interval)

if __name__ == '__main__':
	# app.run()
	socketio.run(app)