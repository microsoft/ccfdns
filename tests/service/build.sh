#!/bin/sh

mkdir -p docker-context

if [[ -f "authorized_keys" ]]; then
  cp authorized_keys docker-context
else
  touch docker-context/authorized_keys
fi

cp service.cpp docker-context
cp run.sh docker-context
cp service.py docker-context
cp requirements.txt docker-context

docker build -t adnscontainers.azurecr.io/adns-test-service -f Dockerfile docker-context
docker push adnscontainers.azurecr.io/adns-test-service

rm -rf docker-context