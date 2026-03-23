# janktun

The jankiest tunneling solution you've ever seen.

## Why?

This tool was developed in response to the on-going (as of March 23) internet shutdown in Iran.

While labeled a "shutdown," BGP routes for Iranian IP ranges remain active, allowing certain whitelisted external IP ranges to transmit packets. Consequently, UDP datagrams can still be received from outside the network if the source address is spoofed to a whitelisted IP.

> See [spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel/) for a more detailed explanation of the shutdown.

While 'spoof tunneling' is not a new concept, both endpoints are expected to be capable of transmitting spoofed packets. **janktun** differs because **only the server** is expected to be capable of spoofing, whereas the client will resort to **DNS tunneling** for upstream traffic.

## Requirements

- Make
- GCC >= 14 (Recent versions of Clang may also work)

## Building & Installation

### Release build

```console
$ make -j$(nproc)
```

### Debug build

```console
$ make -j$(nproc) DEBUG=1
```

### Installation

```console
# make install
```

> See [dist](dist/) directory for systemd service files and configuration samples.

## Usage

```
Usage: janktun [OPERATION] [OPTION...]

Options:
   -n <domain>       domain name
   -v <verbosity>    set logging verbosity (DEBUG, INFO, ERROR - default: INFO)
   -h                show this help message

 Oeprations:
   server            run server
   client            run client

 Server options:
   -l <addr[:port]>  DNS listen address (default: [::]:53)
   -d <addr:port>    downstream destination address
   -s <addr[:port]>  downstream source address (optional)
   -D <addr:port>    destination address

 Client options:
   -l <addr:port>    inbound listen address
   -d <addr:port>    downstream listen address
   -s <addr:port>    downstream source address (optional)
   -L <length>       maximum domain length (default: 253)
   -r <addr[:port]>  resolver(s), can be specified multiple times up to 16 times
```

## Architecture: IP Spoof + DNS Tunnel Combo

- **Upstream (client → server)**: The client encapsulates UDP datagrams (e.g., WireGuard) into DNS queries, which are routed to the server via recursive resolvers.

- **Downsteram (server → client)**: The server transmits raw UDP datagrams directly to the client by spoofing the source address to match a trusted endpoint.

This is why **janktun** is significantly faster than standard bidirectional DNS tunneling; it removes the resolver bottleneck from the downstream path while keeping the client-side configuration simple and "spoof-free."

> **janktun** does *NOT* perform any encryption or authentication on transmitted data; the underlying tunnelled protocol is expected to perfom them.
