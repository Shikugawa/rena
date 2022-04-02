# Rena

A user-space asynchronous TCP/IP protocol library

## Setup

It uses [ayame](https://github.com/Shikugawa/ayame) for building simple network topology to run.
It creates a simple topology using linux network namespaces and injects iptable configs for experiment. 

```
sudo ayame create -c ayame.yaml
```

## Run

We prepared sample programs using this library for integration test.

```
> sudo ip netns exec ns1 /bin/bash
(inside ns1) > RUST_LOG=info target/debug/examples/tcp_local -i link1-left -d 10.0.0.2/24 -p 8000
```
