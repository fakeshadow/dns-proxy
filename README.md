# dns-proxy is a simple dns forward.

## Features

- UDP proxy.
- DoT(DNS over TLS) proxy.
- DoH(DNS over HTTPS) proxy.

## Requirement

- rustc 1.70.0-nightly (ff4b772f8 2023-03-10)

## Build

```shell
$ cargo build --all-features --release
```

## Usage

```
Usage: [-l LISTEN] -u UPSTREAM [-b BOOT_STRAP] [-L LOG_LEVEL] [-t THREAD]

Available options:
    -l, --listen <LISTEN>         Local listening address for proxy
    -u, --upstream <UPSTREAM>     Upstream server for dns look up
    -b, --bootstrap <BOOT_STRAP>  Bootstrap dns for resolving DoT/DoH upstreams
    -L, --log-level <LOG_LEVEL>   Display level of logger: error,warn,info,debug,trace. number 1-5 can be used to represent level in the same order from error to trance
    -t, --thread <THREAD>         OS thread count dns-proxy would spawn and opperate on in parralell
    -h, --help                    Prints help information
```
