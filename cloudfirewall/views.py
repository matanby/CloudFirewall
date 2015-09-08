from flask import Flask, send_from_directory, make_response, jsonify, request
from flask.ext.login import LoginManager, current_user, login_user, login_required, logout_user
from models import User
from forms import LoginForm
# from flask.ext.socketio import SocketIO

import wtforms_json
import datetime
import time

BLOCKED_EVENT_TYPE = "Blocked"
EVENT_TIME = "time"
BLOCKS = "blocks"
EVENT_TYPE = "action"
SESSIONS = "sessions"
DATASETS = "datasets"
PROTOCOLS_FILE = "protocols.txt"


app = Flask(__name__, static_folder='static')
app.debug = True
app.config.from_object('config')
# db = SQLAlchemy(app)

# Init WTForms-JSON to allow populating WTForms from JSON content.
wtforms_json.init()

# Init web sockets framework
# socketio = SocketIO(app)

# Init the login manager and the admin user
login_manager = LoginManager()
login_manager.init_app(app)
admin = User("admin")

# Init the firewall instance
# firewall = ipc.get_proxy_by_name("firewall")
import xmlrpclib
firewall = xmlrpclib.ServerProxy('http://192.168.1.2:9000')

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
		events = firewall.get_events(time.time() - 60*30, time.time())
		for event in events:
			event["time"] = time.ctime(event["time"])
		return success('Events table retrieved succesfuly', 200, events)
	except:
		return fail('Could not retrieve events table')

@app.route('/mode', methods=['GET'])
@login_required
def get_mode():
	"""

	"""
	try:
		mode = firewall.get_mode()
		return success('Firewall Mode retrieved succesfuly', 200, mode)
	except Exception,e:
		print e
		return fail('Could not retrieve firewall mode')

@app.route('/mode', methods=['POST'])
@login_required
def set_mode():
	"""

	"""
	try:
		mode = request.get_json()['mode']
		firewall.set_mode(mode)
		return success('Firewall Mode retrieved succesfuly', 200, mode)
	except Exception, e:
		print e
		return fail('Could not change firewall mode')

@app.route('/rules', methods=['GET'])
@login_required
def rules_table():
	"""

	"""
	try:
		return success('Rules table retrieved succesfuly', 200, firewall.get_active_rules())
	except:
		return fail('Could not retrieve firewall rules table')

@app.route('/rules', methods=['POST'])
@login_required
def add_rule():
	try:
		rule = request.get_json()
		firewall.add_rule(rule['direction'], rule['sourceIp'], rule['destinationIp'],
							 rule['protocol'] , rule['sourcePort'], rule['destinationPort'])
		return success('New Rule added succesfuly', 200, rule)
	except:
		return fail('Cannot add rule to firewall')

@app.route('/rules', methods=['PUT'])
@login_required
def edit_rule():
	try:
		rule = request.get_json()
		firewall.edit_rule(int(rule['id']) - 1, rule['newDirection'], rule['newSourceIp'], rule['newDestinationIp'],
							rule['newProtocol'], rule['newSourcePort'],rule['newDestinationPort'])

		return success('Rule data changed successfully', 200, rule)
	except:
		return fail('Could not edit rule')

@app.route('/rules', methods=['DELETE'])
@login_required
def delete_rule():
	try:
		rule = request.get_json()
		firewall.delete_rule(rule["id"] - 1)
		return success('Rule deleted succesfuly', 200, rule)
	except:
		return fail('Could not delete the rule from firewall')

# @socketio.on('get_events')
# @login_required
# def handle_message():
# 	print "user connected to get events socket"

def events_updater():
	import threading
	threading.Timer(50000.0, events_updater).start()
	# socketio.emit('event_occured', firewall.get_events())
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

		last_10_mins_events = firewall.get_events(time.time() - 10*60, time.time())

		for event in last_10_mins_events:
			event_time_mins = int(event["time"]) / 60
			ten_mins_ago_time = time.time() - 10*60
			time_interval = event_time_mins - (int(ten_mins_ago_time) / 60)
			barChartData[DATASETS][SESSIONS][time_interval] += 1

			if event[EVENT_TYPE] == BLOCKED_EVENT_TYPE:
				barChartData[DATASETS][BLOCKS][time_interval] += 1

		return success('Stats table retrieved succesfuly', 200, barChartData)

	except:
		return fail('Could not retrieve blocks per session by interval stats')

@app.route('/ProtocolStats', methods=['GET'])
@login_required
def get_sessions_per_protocol():

	try:

		pieChartData = {}

		for event in firewall.get_events(time.time() - 10*60, time.time()):
			dst_port = event["dst_port"]
			if dst_port in PROTOCOLS_BY_PORT:
				protocol = PROTOCOLS_BY_PORT[dst_port] + " (%s)" % dst_port
			else:
				protocol = str(dst_port)

			if protocol not in pieChartData:
				pieChartData[protocol] = 1
			else:
				pieChartData[protocol] += 1

		return success('Stats table retrieved successfully', 200, pieChartData)
	except:
		return fail('Could not retrieve protocol stats')

@app.route('/SessionsPerDirectionStats', methods=['GET'])
@login_required
def get_sessions_per_direction():

	try:
		pieChartData = {
			"Incoming": 0,
			"Outgoing": 0
		};

		for event in firewall.get_events(time.time() - 60*10, time.time()):
			pieChartData[event["direction"]] += 1

		return success('Stats table retrieved successfully', 200, pieChartData)

	except:
		return fail('Could not retrieve sessions per direction stats')

def read_protocols():
	prots = {}
	with open(PROTOCOLS_FILE, 'r') as f:
		for line in f.readlines():
			fields = line.split('\t')
			prot_no = int(fields[0].strip())
			proto_name = fields[1].strip()
			proto_desc = fields[2].strip()
			prots[prot_no] = proto_name

	return prots





if __name__ == '__main__':
	PROTOCOLS_BY_PORT = read_protocols()
	app.run()
	# socketio.run(app)
	pass