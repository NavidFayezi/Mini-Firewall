#!/bin/sh

iptables -A INPUT -p udp -j QUEUE
