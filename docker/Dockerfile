# Image for every drone / GS / user container.
# Build once inside the VM:   docker build -t fanet-node:latest docker/
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 iputils-ping net-tools iperf3 tcpdump python3 && \
    rm -rf /var/lib/apt/lists/*
CMD ["/bin/bash"]
