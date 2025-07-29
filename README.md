# XLESS

XLESS is a modern, highly obfuscated, and extremely secure proxy forwarding tool that supports HTTP/3 & UDP. It is designed for anti-detection and anti-interference scenarios, featuring real website traffic obfuscation, deep disguise of authentication requests, and transparent decoy reverse proxy capabilities. XLESS is ideal for high-threat environments where active probing and passive traffic analysis are concerns.

## Features

  - **Full-Link uQUIC/HTTP/3 Support**: Ensures high efficiency, low latency, and cross-platform compatibility.
  - **Highly Obfuscated Authentication & Traffic**: Authentication requests can mimic any real website API, making all traffic appear as normal web behavior.
  - **Transparent Decoy/Front-End Reverse Proxy**: All unauthenticated traffic is transparently forwarded to a decoy, showing no proxy characteristics.
  - **Intelligent UDP/BBR/Bandwidth Detection**: Features smart congestion control and supports various transmission optimizations.
  - **Multiple Protocol Ingress**: Supports SOCKS5, HTTP, TUN, and TCP/UDP transparent proxy modes.
  - **Flexible ACLs, Egress Links, and Real-time Traffic Statistics**: Provides comprehensive control and monitoring.
  - **Customizable Parameters**: Allows for custom obfuscation, passwords, certificates, decoy sites, uQUIC, and more.

-----

## Quick Start

### 1\. Installation

It is recommended to compile with Go 1.22+ for optimal performance:

```bash
git clone https://github.com/XLESSGo/XLESS.git
cd XLESS
go build -o xless ./cmd/xless
```

Alternatively, you can download pre-compiled binaries from the [Release page](https://github.com/XLESSGo/XLESS/releases).

-----

### 2\. Configuration Files

#### Client Configuration (`client.yaml`)

```yaml
server: your.server.domain:443
auth: your_password

decoyURL: "https://www.example.com"    # Required! The actual address of the decoy website.

obfs:
  type: salamander
  password: your_obfs_password

tls:
  sni: www.example.com
  insecure: false

quic:
  # ... Optional QUIC parameters ...
  maxIdleTimeout: 20s

bandwidth:
  up: 200mbps
  down: 1gbps

socks5:
  listen: 127.0.0.1:1080
```

#### Server Configuration (`server.yaml`)

```yaml
listen: :443

decoyURL: "https://www.example.com"    # Required! The actual address of the decoy website.

auth:
  type: password
  password: your_password

obfs:
  type: salamander
  password: your_obfs_password

tls:
  cert: fullchain.pem  # Optional, use your own or use protean to generate server cert according to DecoyURL
  key: privkey.pem

quic:
  maxIdleTimeout: 20s
```

**Note**: `decoyURL` must be a real, accessible HTTPS site. It is recommended to match it with your SNI for optimal disguise effectiveness.

-----

### 3\. Start the Server

```bash
./xless server -c server.yaml
```

### 4\. Start the Client

```bash
./xless client -c client.yaml
```

Upon successful startup, the client will automatically listen on a local port (e.g., 1080). You can then configure your browser or system proxy to use it as a SOCKS5 or HTTP proxy.

-----

## Advanced Usage

### Transparent Proxy & TUN

Multiple ingress modes can be enabled simultaneously, supporting transparent proxy and TUN tunnels for global proxy or traffic splitting.

```yaml
socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080

tun:
  name: hytun
  mtu: 1500
  address:
    ipv4: 10.10.0.2/30
```

### Bandwidth & Rate Limiting

You can limit upload/download bandwidth using the `bandwidth` field. Units supported include `kbps`, `mbps`, and `gbps`.

### Multi-Egress & ACL

The server supports advanced features like multi-egress, traffic splitting, ACLs, and DNS spoofing. Refer to the configuration templates and the [official Wiki](https://github.com/XLESSGo/XLESS/wiki) for detailed information.

-----

## Obfuscation and Decoy Mechanism Explained

  - When the client starts, it first automatically simulates decoy website Browse behavior (e.g., visiting the homepage, randomly requesting resources), fully mimicking normal user traffic.
  - Authentication requests use forged API paths, parameters, headers, and body, allowing the server to automatically identify them without fixed characteristics.
  - All HTTP/3 requests are reverse proxied to the `decoyURL` until authentication is successful. Failed authentication or illegal requests will also only return decoy responses.
  - After successful authentication, it switches to the real proxy channel, with all traffic continuing to maintain obfuscation, fragmentation, and delay characteristics.

-----

## Frequently Asked Questions

**Q: What is `decoyURL` for, and why is it required?**
A: It determines the real destination for all obfuscated/unauthenticated traffic. It must be a real, accessible HTTPS site; otherwise, the proxy might expose its characteristics or fail to forward traffic correctly.

**Q: How do I generate a self-signed TLS certificate?**
A: We recommend using free certificates from Let's Encrypt. If you need a self-signed certificate, you can use:

```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=your.server.domain"
```

**Q: Which platforms are supported?**
A: Linux, macOS, Windows, and FreeBSD, supporting ARM/x86\_64 architectures.

**Q: Does it support UDP/QUIC transparent proxy?**
A: Yes, you can enable it by configuring `UDPForwarding`, `UDPTProxy`, and other related fields in both client and server configurations.

-----

## Contribution and Feedback

  - Issues and Pull Requests are welcome on the [project homepage](https://github.com/XLESSGo/XLESS).
  - Find our QQ group/Telegram channel on the Wiki page.

-----

## License

MIT License

-----
