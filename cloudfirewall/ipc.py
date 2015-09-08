import Pyro4

_PYRO_NAME_PREFIX = 'PYRONAME:'


def get_proxy_by_name(name):
	"""
	Create a Pyro proxy for an async message handler.
	"""

	try:
		return Pyro4.Proxy('%s%s' % (_PYRO_NAME_PREFIX, name))

	except Exception, e:
		print("Couldn't retrieve the proxy for %s. Error: %s" % (name, e))
		return None
