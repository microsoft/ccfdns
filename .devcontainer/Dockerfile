FROM mcr.microsoft.com/ccf/app/dev:5.0.0-dev13-sgx

RUN curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt-get install -y nodejs

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y clang-10 clang-11 libstdc++-10-dev libcurl4-openssl-dev libssl-dev

RUN wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"
ENV GOPATH="usr/local/go"

## Install Pebble
RUN git clone https://github.com/letsencrypt/pebble/
WORKDIR /pebble
RUN go install ./cmd/pebble
