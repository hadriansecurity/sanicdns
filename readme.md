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

This section provides instructions for installing precompiled AF_XDP binaries to get started quickly.

```bash
curl -sSL https://raw.githubusercontent.com/hadriansecurity/sanicdns/main/install.sh | sudo bash
```

## Getting started

1. Setup 1Gb of hugepages (Allocate more when out of memory)
   ```bash
   sudo dpdk-hugepages.py --setup 1G
   ````
2. Get a wordlist to use
   For getting started you can use the `majestic_million.txt` file in the SanicDNS Repo
   ```bash
   wget https://raw.githubusercontent.com/hadriansecurity/sanicdns/main/majestic_million.txt
   ```
3. Run the tool
   ```bash
   sudo sanicdns -i majestic_million.txt -l log.txt -r 2000 -c 10000 --resolvers 1.1.1.1,1.0.0.1
   ````

## Command line flags
```
  -h, --help            print this help screen
      --version         print the version and exit
      --headless        run in headless mode (no terminal UI)
  -w, --cores           number of cores to use (default: 2)
  -r, --rate            scan rate in [packets per second] (default: 1000)
  -c, --num-concurrent  max number of concurrent DNS requests
                           (default: rate/5)
  -t, --timeout         timeout [ms] (default: 15'000)
      --num-retries     number of retries (default: 10)
  -g, --gateway-ip      IP address of gateway
  -s, --static-ip       own (static) IP address
  -m, --gateway-mac     gateway mac, ARP will be used if no MAC is specified
  -d, --device-name     Device name (example: 0000:2e:00:0)
  -i, --input-file      Path of input file with domains
  -x, --xdp-path        Path to XDP program
      --resolvers       Resolvers (default 1.1.1.1,1.0.0.1), either:
                            1. Comma-seperated list of IP's
                            2. File with a resolver specified on each line
      --rcodes          Only output results with these DNS return codes
                             Example: --rcodes R_NOERROR,R_SERVFAIL
      --prefix          Prefix to add to each line of the input
      --postfix         Postfix to add to each line of the input
  -l, --log-path        Log file path, logging will be enabled when a log path 
                          is set
  -o, --output-path     output path (default: output.txt)
      --output-raw      output raw DNS packets in hex (from DNS header to end 
                          of packet)
      --no-huge         Don't use huge pages
      --debug           Print debug information
  -q, --q-type          Question type
                          (T_A, T_NS, T_CNAME, T_DNAME, T_SOA, T_PTR, T_MX, T_-
                          TXT, T_AAAA, T_OPT)
```
