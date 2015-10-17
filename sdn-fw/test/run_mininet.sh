#!/usr/bin/env bash

sudo mn -c && sudo mn --custom ./topo.py --topo TwoNetworksTopology --link tc --mac --switch ovsk --controller=remote
