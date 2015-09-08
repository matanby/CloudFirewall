#! /usr/bin/env python

if __name__ == '__main__':
	import sys
	sys.path.insert(0, '/home/mininet/pox')

	import pox.boot
	pox.boot.boot()
