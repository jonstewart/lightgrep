FROM ubuntu:22.04 as base

RUN apt-get update \
    && apt-get -y install g++ gdb llvm clang lldb \
    	make autoconf automake libtool pkg-config \
    	bison libboost-all-dev

WORKDIR /app

FROM base as dev
