FROM 24e044b795288bc851bbf81da183e7a9
ARG DEBIAN_FRONTEND=noninteractive
COPY 082b96ec819c95ae773daebde675ef80 /start.sh
COPY d18858afc6bb66ec3a19d872077acfd2 /seedemu_sniffer
COPY 17ac2d812a99a91e7f747e1defb72a29 /seedemu_worker
RUN chmod +x /start.sh
RUN chmod +x /seedemu_sniffer
RUN chmod +x /seedemu_worker
COPY e01e36443f9f72c6204189260d0bd276 /ifinfo.txt
COPY d3d51fdf7f4bad30dc5db560a01ce629 /interface_setup
COPY f4d556a844298d3911e6d250e4a2d93b /tmp/eth-genesis.json
COPY d0c504021778634cd94fd96c80ae358d /tmp/keystore/UTC--2026-04-12T17-51-35.613083000Z--0x8c400205fDb103431F6aC7409655ad3cf8f6d007
COPY 33cd6d6b274ee889da140ae8cc0f8bdd /tmp/keystore/UTC--2026-04-12T17-51-36.387215000Z--0x9105A373ce1d01B517aA54205A5E4c70FA9f34Fe
COPY d2cdff8371aa6af79bb63954a87ac69f /tmp/eth-password
COPY 0bf749f51915d190035e14f6afa9a371 /tmp/eth-nodes
COPY 427fecb1e0b6c8dc8f669b5b71b8db71 /tmp/eth-bootstrapper
RUN pip3 install 'web3>=6,<7'
CMD ["/start.sh"]

