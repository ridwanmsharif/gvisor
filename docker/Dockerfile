FROM debian:stable
  
RUN apt update
RUN apt install -y build-essential git pkg-config fuse3 libfuse3-3 libfuse3-dev strace

WORKDIR /fus

RUN mkdir -pv nomount

RUN git clone https://github.com/libfuse/libfuse
RUN git clone https://github.com/jinmouil/short-syscalls

RUN gcc -Wall ./libfuse/example/hello.c `pkg-config fuse3 --cflags --libs` -o hello
RUN bash -c 'for f in ./short-syscalls/*.c; do gcc -Wall -o "${f/.c/.run}" "$f"; done'

CMD ["bash"]
