#!/bin/sh
uci set wireless.@wifi-iface[0].channel=$1
uci commit wireless