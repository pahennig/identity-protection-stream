#!/bin/bash
SHELL=/bin/bash
PWD=/root
PATH=/sbin:/bin:/usr/sbin:/usr/bin

mydir=/home/ec2-user/repo_dir

docker run \
    -h hostname \
    -v $mydir:/usr/app \
    prh/identity-protection-stream 192.168.0.132 514