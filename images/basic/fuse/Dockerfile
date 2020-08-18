FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            wget \
            git \
            pkg-config \
            zip \
            g++ \
            zlib1g-dev \
            unzip \
            python3 \
        && rm -rf /var/lib/apt/lists/*
RUN wget https://github.com/bazelbuild/bazel/releases/download/0.27.0/bazel-0.27.0-installer-linux-x86_64.sh
RUN chmod +x bazel-0.27.0-installer-linux-x86_64.sh
RUN ./bazel-0.27.0-installer-linux-x86_64.sh

RUN mkdir abseil-cpp && cd abseil-cpp \
    && git init && git remote add origin https://github.com/abseil/abseil-cpp.git \
    && git fetch --depth 1 origin 43ef2148c0936ebf7cb4be6b19927a9d9d145b8f && git checkout FETCH_HEAD

RUN apt-get update && apt-get install -y software-properties-common

RUN apt update
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get install -y build-essential git pkg-config fuse3 libfuse3-3 libfuse3-dev strace
RUN apt-get install -y procps vim libstdc++6

WORKDIR /fus

RUN mkdir -pv mountpoint

RUN git clone https://github.com/libfuse/libfuse
RUN git clone https://github.com/jinmouil/short-syscalls

RUN gcc -Wall ./libfuse/example/hello.c `pkg-config fuse3 --cflags --libs` -o hello
RUN bash -c 'for f in ./short-syscalls/*.c; do gcc -Wall -o "${f/.c/.run}" "$f"; done'

COPY server-bin ./server-bin

CMD ["bash"]
