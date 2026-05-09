# Model Creation Steps

## Running the Simulation

- Without UI:

```bash
docker-compose -f docker-compose.uml up --build 
```

- With UI:

```bash
docker-compose -f docker-compose.uml -f docker-compose.ui.yml up --build 
```

Improving performance:

- In `docker-compose.yml`, lower the value of the `cpus` fields

> The lower the value, however, the longer the simulation will need to run in order to obtain enough packets to use as reference for AI models.

## Normal Behaviour Capture

1) Set the GEN_ETH_TRAFFIC and GEN_EXTRA_TRAFFIC (if desired) to `"true"` in `docker-compose.yml`.
2) Run the simulation.
3) Run `sudo ./capture.sh`. This should generate a new subfolder in the `captures/` folder with 4 different pcap files.
4) After the desired length of time, terminate `./capture.sh`.
5) Use the `merge_pcap.sh` to create the final pcap file:

```bash
merge_pcap.sh <path to capture folder> <output file name>
```

## Malicious Behaviour Capture

### Synflood

1) Set the GEN_ETH_TRAFFIC and GEN_EXTRA_TRAFFIC (if desired) to `"true"` in `docker-compose.yml`.
2) Run the simulation.
3) Run `sudo ./capture.sh`.
4) Run the ```synflood``` tool

```bash
sudo ./synflood <victim IP> <victim port>
```

5) Terminate `./capture.sh`.
6) Use the `merge_pcap.sh` to create the final pcap file:

```bash
merge_pcap.sh <path to capture folder> <output file name>
```

### Eclipse

## Training the Models

1) Separate all pcap files into two folders, depending on whether they are malicious or not.
2) Use the `train_models.py` tool.

```bash
python train_models.py --normal <path to folder of "normal" pcap files> --malicious <path to folder with malicious pcap files>
```

3) Observe and analyse the results.


> Recommendation: use a python environment instead of the system's python installation. Inside it, run `pip install nfstream scikit-learn pandas joblib` first.

## Deploying the Models
