#!/bin/bash

readonly project_root=$(dirname "$(dirname "$0")")
proxychains4 -f "$project_root/misc/proxychains.conf" iperf -c 127.0.0.1
