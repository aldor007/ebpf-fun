# ebpf-fun

eBPF program using XDP for listing to incoming connection for given network interface. Example from cilium/ebpf helped this program to happen 

# Building

Building application requires libbpf-dev and other installation script for Ubuntu/Debian is provided in `install.sh` file
```bash
./install.sh
```

## Building app

```bash
make
```

## Usage

You can set on what network interface application should attach XDP program (default: eth0)
```bash
$ ./app -h    
Usage of ./app:
  -iface string
        Interface name to attach XDP program (default "eth0")
```

Running app requires root permissions

```bash
$ sudo ./app
2022/02/18 20:47:52 Listening for events..
Server listen on :8081
2022/02/18 20:47:55 New connection: 172.21.240.1:57621 -> 172.21.255.255:57621 
```

Running inside of a container (using docker-compose)

```bash
make up
```

# Materials to check out

* https://github.com/lizrice/ebpf-beginners - list of video talks with code examples (C, python, go)
* https://github.com/xdp-project/xdp-tutorial - XDP tutorials C user-space code
* https://github.com/cilium/ebpf - golang lib 
* https://github.com/cilium/ebpf/tree/master/examples - examples from you can start writing you own eBPF app 
