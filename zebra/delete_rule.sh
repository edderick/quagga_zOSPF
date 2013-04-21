#! /bin/bash

ip -6 rule del from $1 table $2
