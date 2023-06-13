#!/bin/sh

curl https://ifconfig.me > /etc/ip

cd /app
g++ -I include -o service service.cpp
./service

cd -
pip install -r requirements.txt

python3 service.py > service.log 2>&1

/usr/sbin/sshd -D
