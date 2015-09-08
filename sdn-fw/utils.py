from threading import RLock
import yaml


class Container(object):
	"""
	This is a general use super class that should
	be used as a parent for specific container classes.
	This class implements auto assignment of allowed attributes on init.
	"""

	def _set_attributes(self, **kwargs):
		"""
		Sets attributes of this container from a kwargs dictionary.
		If exists a key in the kwargs dictionary which does not have
		a corresponding attribute (an attribute with the same name
		as the key), an AttributeError will be raised.
		:param kwargs: The dictionary of key:value to assign as attributes.
		:return: None.
		"""
		for k, v in kwargs.iteritems():
			if not hasattr(self, k):
				raise AttributeError('Invalid attribute %s' % k)

			self.__dict__[k] = v

	def __str__(self):
		attributes = ', '.join('%s: %s' % (k, v) for k, v in sorted(self.__dict__.iteritems()))
		return '%s: (%s)' % (self.__class__.__name__, attributes)

	def __eq__(self, other):
		for k, v in self.__dict__.iteritems():
			if not hasattr(other, k):
				return False

			if getattr(other, k) != getattr(self, k):
				return False

		return True


class Singleton(type):
	_instances = {}
	_lock = RLock()

	def __call__(cls, *args, **kwargs):
		with Singleton._lock:
			if cls not in cls._instances:
				cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
			return cls._instances[cls]

	def instance(cls):
		return cls.__call__()


def load_yaml(file_name):
	with open(file_name, 'r') as conf_file:
		return yaml.load(conf_file)


def dump_yaml(file_name, data):
	with open(file_name, 'w') as conf_file:
		return yaml.dump(data, conf_file, default_flow_style=False, indent=4)
