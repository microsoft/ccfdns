FROM mcr.microsoft.com/ccf/app/dev:5.0.0-dev13-sgx

RUN curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt-get install -y nodejs

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y clang-10 clang-11 libstdc++-10-dev libcurl4-openssl-dev libssl-dev