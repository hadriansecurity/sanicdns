Compiling from source
+++++++++++++++++++++

The installation instructions in this section are tested on Ubuntu 24.04, other distros / Ubuntu versions are not guaranteed to work.

Prerequisites
-------------

Before compiling the project, ensure you have the following prerequisites installed. You can install all required packages on Ubuntu using the following command:

.. code-block:: bash

    sudo apt-get update && sudo apt-get install -y \
        build-essential \
        cmake \
        ninja-build \
        python3 \
        libelf-dev \
        dpdk \
        dpdk-dev \
        libncurses5-dev \
        liburing-dev \
        software-properties-common \
        linux-headers-generic \
        libbpf-dev \
        libc6-dev \
        libc6-dev-i386 \
        libxdp-dev \
        clang-17

This command will install all the necessary packages in one go.

Compilation Steps
-----------------

1. Clone the repository and navigate to the project directory:

    .. code-block:: bash

        git clone --recursive https://github.com/hadriansecurity/sanicdns.git
        cd sanicdns

2. Create a build directory:

    .. code-block:: bash

       mkdir build


3. Generate build files using CMake:

    .. code-block:: bash
    
        cmake -B build -DCMAKE_GENERATOR=Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=ci/<compiler>-toolchain.cmake -DNIC_TYPE=<nic_type>

   Replace `<compiler>` with either `gcc` or `clang`, and `<nic_type>` with either `AF_XDP` or `I40E`.

4. Build the project:

    .. code-block:: bash

        ninja -C build
