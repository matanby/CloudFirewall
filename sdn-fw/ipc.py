from threading import Thread
from time import sleep

import Pyro4
import Pyro4.errors
from Pyro4.naming import NameServer

_PYRO_NAME_PREFIX = 'PYRONAME:'
_daemon = None


def init(host=None, port=0):
	global _daemon

	Pyro4.expose(NameServer)
	_set_pyro_config()
	_daemon = Pyro4.Daemon(host=host, port=port)


def register_service(service_obj, service_name):
	"""
	Create a Daemon for the current process.
	Register the passed class (or object) to the daemon.
	Register this proxy to the name server.
	Return the URI (might be used again by other classes).
	"""

	uri = _daemon.register(service_obj)

	# Register the proxy URI to the name server with the passed service name.
	ns = _get_name_server()
	ns.register(service_name, uri)

	return uri


def start_request_loop():
	"""
	Starts the daemon's request loop.
	"""

	print('Starting service request loop')
	t = Thread(target=_daemon.requestLoop)
	t.daemon = True
	t.start()


def exit_request_loop():
	"""
	Stops the daemon's request loop, closes sockets, releases resources
	"""

	if not _daemon:
		return

	_daemon.shutdown()
	while _daemon.transportServer:
		sleep(0.1)


def get_proxy_by_name(name):
	"""
	Create a Pyro proxy for an async message handler.
	"""

	try:
		return Pyro4.Proxy('%s%s' % (_PYRO_NAME_PREFIX, name))

	except Exception, e:
		print("Couldn't retrieve the proxy for %s. Error: %s" % (name, e))
		return None


def _set_pyro_config():
	"""
	Sets Pyro configuration parameters.
	"""

	# This is necessary to ensure that the same socket will be reused if the process is restarted
	# Pyro4.config.SOCK_REUSE = True

	# This is necessary to ensure that only explicitly exposed methods will be available for sync calls
	Pyro4.config.REQUIRE_EXPOSE = True

	Pyro4.config.SERIALIZERS_ACCEPTED.add('pickle')
	Pyro4.config.SERIALIZER = 'pickle'


def _get_name_server():
	"""
	Make sure the NS is up, and return it
	"""

	_validate_name_server_is_running()  # Will block until the name-server is up
	return Pyro4.locateNS()  # Calling it once again, to avoid race conditions (might be unnecessary)


def _validate_name_server_is_running():
	"""
	Will loop until the name server is up.
	Used to make sure the name resolving will succeed, before attempting it.
	"""

	while True:
		try:
			Pyro4.locateNS()  # If this call returns without exceptions, the NS is up and running
			break
		except Pyro4.errors.NamingError:
			_launch_name_server()
			sleep(0.1)          # Give the Name Server a chance to load before trying to return it


def _launch_name_server():
	"""
	Start Pyro's name server
	"""

	print('Launching Pyro NameServer')
	t = Thread(target=Pyro4.naming.startNSloop)
	t.daemon = True
	t.start()
