#!/bin/bash

# Function to check system requirements
check_requirements() {
    # Check OS
    if [[ "$(uname)" != "Linux" ]]; then
        echo "Error: sanicdns is only compatible with Linux systems."
        exit 1
    fi

    # Check architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        echo "Error: sanicdns requires x86_64 architecture."
        exit 1
    fi

    # Check kernel version
    kernel_version=$(uname -r | cut -d. -f1,2)
    if ! awk -v ver="$kernel_version" 'BEGIN{if (ver < 5.11) exit 1; exit 0}'; then
        echo "Error: sanicdns requires kernel version 5.11 or higher."
        exit 1
    fi

    # Check number of logical cores
    cores=$(nproc)
    if [[ $cores -lt 2 ]]; then
        echo "Error: sanicdns requires at least 2 logical cores."
        exit 1
    fi
}

# Function to find and download the latest compatible release
find_and_download_release() {
    echo "Searching for the latest compatible sanicdns release..."
    local releases_url="https://api.github.com/repos/hadriansecurity/sanicdns/releases"
    local releases=$(curl -s "$releases_url")
    
    local version
    local url
    
    version=$(echo "$releases" | jq -r '.[] | select(.assets[].name == "sanicdns_af_xdp.tar.gz") | .tag_name' | head -n 1)
    
    if [ -z "$version" ]; then
        echo "Error: Could not find a compatible release with sanicdns_af_xdp.tar.gz"
        return 1
    fi
    
    url=$(echo "$releases" | jq -r ".[] | select(.tag_name == \"$version\") | .assets[].browser_download_url")
    
    echo "Attempting to download sanicdns version $version..."
    if curl -sL -o sanicdns_af_xdp.tar.gz "$url"; then
        echo "Successfully downloaded sanicdns version $version"
        echo "Installing sanicdns version $version"
        return 0
    else
        echo "Failed to download sanicdns version $version"
        return 1
    fi
}

# Function to install sanicdns
install_sanicdns() {
    echo "Installing sanicdns..."
    tar xzf sanicdns_af_xdp.tar.gz
    sudo install sanicdns_af_xdp/sanicdns sanicdns_af_xdp/sanicdns_xdp.c.o /usr/local/bin
    rm -rf sanicdns_af_xdp.tar.gz sanicdns_af_xdp
}

# Function to install dpdk-hugepages
install_dpdk_hugepages() {
    echo "Installing dpdk-hugepages..."
    curl -sSL https://raw.githubusercontent.com/DPDK/dpdk/main/usertools/dpdk-hugepages.py -o dpdk-hugepages.py
    sudo install dpdk-hugepages.py /usr/local/bin
    rm dpdk-hugepages.py
}

# Main installation function
install() {
    if find_and_download_release; then
        install_sanicdns
        install_dpdk_hugepages
        echo "sanicdns installation complete!"
    else
        echo "Installation failed."
        exit 1
    fi
}

# Run checks
check_requirements

# If all checks pass, run installation
install
