#!/bin/sh

iptables -D INPUT -p udp -j QUEUE

