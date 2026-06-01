FROM handsonsecurity/seedemu-ethereum

# Install the necessary network attack tools and Python
RUN apt-get update && apt-get install -y \
    iptables \
    dsniff \
    python3 \
    python3-pip \
    iproute2 \
    net-tools \
    nano

# Install the web3 library for the Python scripts
RUN pip3 install web3 scapy
