# NetHCF: Enabling Line-rate and Adaptive Spoofed IP Traffic Filtering
This is a introduction to our NetHCF project.
## Overview
We propose NetHCF, a line-rate in-network spoofed traffic filtering system. 
To fit the classic Hop-Count Filtering (HCF) scheme into memory-limited and computation-restrictive switching ASICs, we decouple the existing HCF into two complementary parts, and design several effective mechanisms to make NetHCF adapt to end-to-end routing changes, IP popularity varieties, and network activity dynamics.

We implement NetHCF on both software simulator (BMv2) and realistic physical hardware (Tofino Switch) of programmable switching ASICs. The data plane of NetHCF is implemented with P4, while the control plane is written in Python. But due to the non-disclosure agreement with Barefoot, we only open the source code of our BMv2 version.

## Design
### Modeling
We set up a relatively simple model with h1-s1-h2 topology. We assume that h1 acts as a client(normal or attacker) which is ahead of the switch and h2 acts as a server which is behind the server.
### Workflow
Please refer to our paper.
## Test
The method to start the p4 switch is to set up a topology on **mininet** where we run the switch.

1. Open a terminal and enter the directory `bmv2/switch/`
2. Run `run_demo.sh` to start the switch (the data plane of NetHCF) on the topology defined in `topo.py`
3. Run a simple web server and client according to [mininet walkthrough](http://mininet.org/walkthrough/#run-a-simple-web-server-and-client). 
4. Open another terminal, and enter the directory `bmv2/controller/`
5. Run `controller.py` (don't forget to modify parameters in the file) to start the controller (the control plane of NetHCF) to coordinate with the switch
6. Then, just try!

## Source Code
`bmv2/switch/p4src/hop_count.p4`  This is the p4 source code.

`bmv2/switch/p4src/includes/headers.p4`  This is the p4 code which defines the header used in NetHCF.

`bmv2/switch/p4src/includes/parser.p4`  This is the p4 code which defines the parser graph of NetHCF.

`bmv2/switch/topo.py` This script will set up the topology of this model and starts the CLI of p4 switch.

`bmv2/switch/run_demo.sh` Start the data plane on the topology defined in `topo.py` without log.  

`bmv2/switch/commands.txt` There are table entries here, which will be loaded into the swtich by `topo.py`. You can also add the entries manually through CLI.

`bmv2/switch/env.sh` Set p4 related environment variables.

`bmv2/switch/cleanup.sh` Clean up the environment such as the pcap file and accessed webpage.

`bmv2/controller/controller.py` NetHCF's conrol plane program running on CPU, masters the running state of switch and matains a global view.

`bmv2/controller/config.py` Some configurations for control plane.

`bmv2/controller/switch.py` NetHCF data plane interfaces, used for control plane to manage the data plane.

`bmv2/controller/data_structure.py` Data structure used in control plane.
