FROM ubuntu:20.04

ENV TZ=Asia/Dubai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update
RUN echo ***************************************0
RUN apt-get install make
RUN echo ***************************************1
RUN apt-get install libconfig-dev llvm clang libelf-dev build-essential -y
RUN echo ***************************************2
RUN apt-get install iproute2 netcat tcpdump bpftrace -y
RUN echo ***************************************3
RUN apt-get install libpcap-dev gcc-multilib -y
RUN echo ***************************************4
RUN apt-get install linux-tools-$(uname -r) -y
RUN echo ***************************************5
RUN apt-get install curl -y
RUN echo ***************************************6
RUN apt-get install vim -y
RUN echo ***************************************7
RUN apt-get install iputils-ping -y
RUN echo ***************************************8
# RUN apt-get install python3 pip -y
# RUN apt-get install kmod -y
# RUN pip install numpy
# RUN pip install matplotlib
# RUN pip install scapy
WORKDIR /app
# COPY libbpf libbpf
# COPY other other
