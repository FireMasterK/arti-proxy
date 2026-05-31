# arti-proxy

A rotating SOCKS5 proxy built with `arti-client`, `bb8`, and `fast-socks5`.

Each incoming SOCKS `CONNECT` request is forwarded through an Arti-backed client from a `bb8` pool. The pool uses isolated Arti handles so requests rotate across independent Tor usage contexts while still sharing Arti's underlying bootstrap state efficiently.

## Run

```bash
cargo run
```

By default the proxy listens on `127.0.0.1:9050`.

## Environment

The binary supports these environment variables:

- `ARTI_PROXY_LISTEN_ADDR`: socket address to bind, for example `127.0.0.1:9050`
- `ARTI_PROXY_POOL_SIZE`: number of pooled Arti clients, default `8`
- `ARTI_PROXY_REQUEST_TIMEOUT_SECS`: end-to-end SOCKS request timeout, default `30`
- `ARTI_PROXY_NEW_CIRCUIT_PERIOD_SECS`: mapped to Arti's circuit request loyalty and preemptive prediction lifetime, default `120`
- `ARTI_PROXY_MAX_CIRCUIT_DIRTINESS_SECS`: mapped to Arti's max circuit dirtiness, default `600`
- `ARTI_PROXY_CIRCUIT_BUILD_TIMEOUT_SECS`: mapped to Arti's circuit request timeout, default `60`
- `ARTI_PROXY_OPTIMISTIC_STREAMS`: enable Arti optimistic streams, default `true`
- `ARTI_PROXY_STATE_DIR`: optional explicit Arti state directory
- `ARTI_PROXY_CACHE_DIR`: optional explicit Arti cache directory

If you set either `ARTI_PROXY_STATE_DIR` or `ARTI_PROXY_CACHE_DIR`, set both.

Example:

```bash
ARTI_PROXY_LISTEN_ADDR=127.0.0.1:9050 \
ARTI_PROXY_POOL_SIZE=16 \
ARTI_PROXY_NEW_CIRCUIT_PERIOD_SECS=120 \
ARTI_PROXY_MAX_CIRCUIT_DIRTINESS_SECS=600 \
ARTI_PROXY_CIRCUIT_BUILD_TIMEOUT_SECS=60 \
cargo run
```

## Test

Once the proxy is running:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

Using `--socks5-hostname` ensures the destination hostname is handed to the SOCKS server instead of being resolved locally first.

You can also verify a plain HTTP target:

```bash
curl --socks5-hostname 127.0.0.1:9050 http://example.com/
```

## Validation

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```
