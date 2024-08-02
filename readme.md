<div align="center">

# SanicDNS
##### Gotta go fast

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)

<img alt="SanicDNS" height="280" src="sanicdns.png" />
</div>

## What does it do?

SanicDNS is a tool that can resolve DNS requests blazingly fast, with the correct hardware and correct resolvers you can resolve up to 5.000.000 domain names each second. You provide a list with input domains and a list with resolvers, SanicDNS will take care of resolving these domains against the provided resolvers in the fastest way possible.

## What does it not do?

SanicDNS will not (yet):
- Perform wildcard detection
- Do recursive resolving, you'll need external resolvers

## What do I need?

To use SanicDNS you'll need:
- A Linux machine with x86_64 architecture
- At least 2 logical cores
- Kernel version >= 5.11
- Performant DNS resolvers
- A good internet connection

## Installing

TODO: Add link to docs
This section provides instructions for installing precompiled AF_XDP binaries to get started quickly. For instructions on compiling from source, see the docs.

1. Download the latest `sanicdns_af_xdp.tar.gz` release
2. Unpack the archive
   ```bash
   tar xzf sanicdns_af_xdp.tar.gz
   ````
3. Install binaries
   ```bash
   sudo install sanicdns_af_xdp/sanicdns sanicdns_af_xdp/sanicdns_xdp.c.o /usr/local/bin
   ````
4. Install dpdk-hugepages
   ```bash
   wget https://raw.githubusercontent.com/DPDK/dpdk/main/usertools/dpdk-hugepages.py
   sudo install dpdk-hugepages.py /usr/local/bin
   ````

## Getting started

TODO: Add link to docs
1. Setup 1Gb of hugepages (see the docs for how many hugepages are necessary)
   ```bash
   dpdk-hugepages.py --setup 1G
   ````
2. Get a wordlist to use
   For getting started you can use the `majestic_million.txt` file in the SanicDNS Repo TODO: add link
3. Run the tool
   ```bash
   sudo sanicdns -i majestic_million.txt -l log.txt -r 2000 --resolvers 1.1.1.1,1.0.0.1
   ````

