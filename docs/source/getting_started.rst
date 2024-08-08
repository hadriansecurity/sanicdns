Getting started
+++++++++++++++

What is SanicDNS
----------------
SanicDNS is a tool that can resolve DNS requests blazingly fast, with the correct hardware and correct resolvers you can resolve up to 5.000.000 domain names each second. You provide a list with input domains and a list with resolvers, SanicDNS will take care of resolving these domains against the provided resolvers in the fastest way possible.

Quickstart
----------

For the quickstart, see the `Github readme <https://github.com/hadriansecurity/sanicdns>`_

CLI Flags
---------

.. code-block::

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

NIC options
-----------

SanicDNS supports to different NIC options: AF_XDP and I40E. `Data Plane Development Kit <https://en.wikipedia.org/wiki/Data_Plane_Development_Kit>`_ is used as an abstraction layer over both network interface types. A schematic representation of the data flow of both options is visualised in the schematics below.

.. grid:: 2

    .. figure:: images/getting_started/kernel_bypass_af_xdp.svg
       :width: 80%
       :align: center

       AF_XDP operating mode schematic

    .. figure:: images/getting_started/kernel_bypass_dpdk.svg
       :width: 80%
       :align: center

       I40E operating mode schematic


.. _getting_started_af_xdp:
AF_XDP
======

SanicDNS's most easy to use operating mode is the AF_XDP operating mode. `AF_XDP <https://en.wikipedia.org/wiki/Express_Data_Path>`_ is a method for `userspace <https://en.wikipedia.org/wiki/User_space_and_kernel_space>`_ applications to skip the Linux network stack altogether and send and receive packets as close to the network card as possible. A `BPF program <https://en.wikipedia.org/wiki/Berkeley_Packet_Filter>`_ is loaded in the kernel and when a new packet is received by the kernel it is immediately forwarded to the userspace application when it matches the specified filter configuration. AF_XDP also allows userspace applications to forward packets directly into the NIC with as little intervention from the kernel as possible.

.. _getting_started_i40e:
I40E
====

SanicDNS also supports linking I40E devices directly to the userspace application. Custom DPDK drivers are loaded on the PCI device, SanicDNS can bind to the NIC directly for maximum performance. The I40E driver supports 10/25/40 Gbps Intel® Ethernet 700 Series Network Adapters based on the Intel Ethernet Controller X710/XL710/XXV710.

Although this mode provides by far the highest performance it is also quite cumbersome to use since it requires a specific network card and two physical ethernet links to the machine that is used: one for 'regular' traffic and one to the dedicated NIC for SanicDNS.

Tests with the XL710 NIC have shown that SanicDNS can produce 40Mpps in raw DNS request (40GbE line rate) and resolve around 7.5M requests per second (tested with our own DPDK-based resolver). Although these speeds are not too useful for real-world scenario's it's a good learning opportunity for checking out high-performance networking.

TODO: better instructions for using I40E NIC's
