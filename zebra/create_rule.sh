#!/bin/bash

ip -6 rule add from $1 table $2
