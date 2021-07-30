# rxtxcpu

rxtxcpu captures packets in per-cpu streams, optionally writing to per-cpu pcap files. On exit, it reports per-cpu packet counts.

rxtxcpu can assist with behavior validation, configuration comparisons, and providing additional data points on packet steering. It also can be used simply for learning purposes across several topics, including the following.
* [RSS (Receive-Side Scaling)](Documentation/case-studies/observing-rss-on-ixgbe.md)
  * [Basic RSS Validation](Documentation/case-studies/observing-rss-on-ixgbe-basic-rss-validation.md)
  * [Advanced RSS Configuration](Documentation/case-studies/observing-rss-on-ixgbe-advanced-rss-configuration.md)
    * [RSS Hash Fields](Documentation/case-studies/observing-rss-on-ixgbe-advanced-rss-configuration-rss-hash-fields.md)
    * [RSS Hash Key](Documentation/case-studies/observing-rss-on-ixgbe-advanced-rss-configuration-rss-hash-key.md)
    * [RSS Hash Indirection Table](Documentation/case-studies/observing-rss-on-ixgbe-advanced-rss-configuration-rss-hash-indirection-table.md)
    * RSS Hash Algorithm
  * Programmable RSS
  * RSS with eBPF (XDP) and CPUMAP
* RPS (Receive Packet Steering)
* RFS (Receive Flow Steering)
* Vendor Flow Steering Solutions
  * Intel® Flow Director
    * EP (Externally Programmed)
    * ATR (Application Targeting Routing)
* SO_INCOMING_CPU
* SO_ATTACH_REUSEPORT_CBPF
* SO_ATTACH_REUSEPORT_EBPF

## Prerequisites

rxtxcpu requires PACKET_FANOUT_CPU (added to the linux kernel in v3.1).

## Installation

rxtxcpu has build time dependencies on gcc, libpcap-devel, and make. It also has a run time dependency on libpcap. libpcap installation is not explicitly included in the following steps since libpcap is a dependency of libpcap-devel. However, please take this into account when building and installing on separate hosts. These package names may vary slightly between distros.

Install build time dependencies on CentOS.
```
sudo yum install gcc libpcap-devel make
```

Install build time dependencies on Ubuntu.
```
sudo apt-get install gcc libpcap-dev make
```

Build.
```
make
```

Install.
```
sudo make install
```

## Usage

### Basic usage

The most basic invocation of rxtxcpu will capture packets until receiving a SIGINT signal (e.g. via Ctrl-C) or SIGTERM signal. Upon SIGINT initiated exit, it will display per-cpu packet counts.

```
rxtxcpu       # packets from any interface
rxtxcpu eth0
```

### Capture rx only

```
rxcpu eth0
```

```
rxtxcpu -d rx eth0
```

### Capture tx only

```
txcpu eth0
```

```
rxtxcpu -d tx eth0
```

### Capture N packets

Supply a count and rxtxcpu will display per-cpu packet counts and exit after receiving that number of packets.

```
rxtxcpu -c100 eth0
```

### Write to per-cpu pcap files

The supplied pcap filename will be used as a template for per-cpu pcap filenames ("-<span>&#60;</span>cpu<span>&#62;</span>" is injected just before the .pcap extension when present, otherwise appended to the end).

```
rxtxcpu -w test.pcap eth0
```

### Capture on a subset of cpus

Both of these will capture only on cpus 0, 2, 3, 4, and 6.

```
rxtxcpu -l 0,2-4,6 eth0
```

```
rxtxcpu -m 5d eth0
```

### Pipe pcap data to tcpdump

When capturing on a single cpu the pcap data can be written to stdout and piped to other pcap capable utils. Using packet buffered output is recommended for this usage.

```
rxtxcpu -l2 -w - -U eth0 | tcpdump -c100 -Snnr -
```

## Contributing

Bug reports and pull requests are welcome. Please see our [contributing guide](CONTRIBUTING.md).

## Testing

Vagrant is used for consistent test environments.

To spin up the CentOS 7 enviroment, build, and run the tests use the following. This will clean up the vm.
```
./runner.sh
```

If developing new tests, it can be convenient to keep the environment around for several runs. This will leave the vm in place.
```
RUNNER_VAGRANT_DESTROY=false ./runner.sh
```

Testing against alternate distros is also available. See the Vagrantfile for available machine names (distros).
```
RUNNER_VAGRANT_MACHINE=bionic ./runner.sh
```

## Versioning

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## License
rxtxcpu is available as open source under the terms of the [MIT license](LICENSE).

## Compatibility

rxtxcpu has been tested on the following distros.

* CentOS 7
* Ubuntu 14.04
* Ubuntu 16.04
* Ubuntu 18.04
