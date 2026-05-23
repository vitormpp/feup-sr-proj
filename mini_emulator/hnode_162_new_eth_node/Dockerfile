FROM 707ec7fa5d3740bf02573cbd0b37e6ea
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils ipcalc iproute2 iputils-ping jq mtr-tiny nano netcat tcpdump termshark vim-nox zsh
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils ipcalc iproute2 iputils-ping jq mtr-tiny nano netcat tcpdump termshark vim-nox zsh
COPY 082b96ec819c95ae773daebde675ef80 /start.sh
COPY d18858afc6bb66ec3a19d872077acfd2 /seedemu_sniffer
COPY 17ac2d812a99a91e7f747e1defb72a29 /seedemu_worker
RUN chmod +x /start.sh
RUN chmod +x /seedemu_sniffer
RUN chmod +x /seedemu_worker
COPY e01e36443f9f72c6204189260d0bd276 /ifinfo.txt
COPY d3d51fdf7f4bad30dc5db560a01ce629 /interface_setup
COPY attacks.py /attacks.py
COPY synflood /synflood
# Eclipse ARP attack dependencies (L2)
COPY arp_eclipse_attack.py /arp_eclipse_attack.py
COPY arp_spoof.py /arp_spoof.py
RUN apt-get update && apt-get install -y --no-install-recommends \
        cpulimit \
        iptables \
        python3-scapy \
    && rm -rf /var/lib/apt/lists/*
COPY bgp_eclipse_attack.py /bgp_eclipse_attack.py
RUN apt-get update && apt-get install -y --no-install-recommends \
        docker.io \
    && rm -rf /var/lib/apt/lists/*
CMD ["/start.sh"]
