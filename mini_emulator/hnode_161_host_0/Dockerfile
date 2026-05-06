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
COPY dcc02698359140fb6eec1903522904d6 /tmp/keystore/UTC--2026-04-12T17-51-33.989516000Z--0x1081c645CC8c21EfbB0114eAc5fcDBE01a1a4b19
COPY c47d926f4d91bfbced75f81e9349df62 /tmp/keystore/UTC--2026-04-12T17-51-34.804469000Z--0xa6bBf9891a0689Fe91d9c1538478b95effe0a57A
COPY d2cdff8371aa6af79bb63954a87ac69f /tmp/eth-password
COPY 0bf749f51915d190035e14f6afa9a371 /tmp/eth-nodes
COPY 427fecb1e0b6c8dc8f669b5b71b8db71 /tmp/eth-bootstrapper
CMD ["/start.sh"]

