# XLESS Protocol Specification

XLESS is a TCP and UDP proxy protocol built on QUIC, designed to provide speed, security, and censorship resistance. This document describes the protocol used by XLESS starting from version 1.0.1. From now on, we will refer to it as "the protocol" or "the XLESS protocol."

## Language Requirements

The keywords "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Underlying Protocol and Data Formats

The XLESS protocol **MUST** be implemented on top of the standard QUIC transport protocol (RFC 9000) and the [Unreliable Datagram Extension](https://www.google.com/search?q=https://www.ietf.org/archive/id/draft-ietf-quic-datagram-03.html).

All multi-byte numbers **MUST** use big-endian format.

All variable-length integers ("varints") **MUST** be encoded/decoded consistently with how they are defined in QUIC (RFC 9000).

-----

## Authentication and HTTP/3 Obfuscation

One of the key features of the XLESS protocol is that for third parties without correct authentication credentials (whether they are middlemen or active probes), the XLESS proxy server behaves exactly like a standard HTTP/3 Web server. Furthermore, the encrypted traffic between the client and server is indistinguishable in appearance from normal HTTP/3 traffic.

Therefore, an XLESS server **MUST** implement an HTTP/3 server (as defined by RFC 9114) and process HTTP requests like any standard Web server. To prevent active probes from detecting common response patterns in XLESS servers, implementers **SHOULD** recommend that users either host actual content or set it up as a reverse proxy for another site.

After the QUIC connection is established and the handshake is completed, the XLESS server **MUST** immediately enter a transparent forwarding state. In this state, the XLESS server acts as a Man-in-the-Middle (MITM) proxy, transparently forwarding every client packet to a pre-configured, legitimate, publicly accessible decoy web service. The XLESS server **MUST** ensure that a connection has been established with the decoy web service and is ready for forwarding. This transparent forwarding of all client packets **MUST** continue uninterrupted until the server receives a specific XLESS authentication request packet.

During this transparent forwarding phase, the XLESS client **MUST** engage in simulated normal web Browse activity with the decoy service:

  * The client's first request **MUST** be for the decoy service's `index.html` page.
  * Upon receiving the `index.html` response, the client **MUST** parse the page to find included link paths (e.g., image, CSS, JS links). The client **MUST** then randomly select 2 to 4 of these link paths and request them in sequence.
  * If `index.html` contains fewer than 2 to 4 link paths, the client **MUST** request all available link paths.
  * If no link paths are found in `index.html`, the client **MUST** immediately proceed to the XLESS authentication phase.

After completing the simulated Browse described above, or if no link paths were found, the XLESS client will send an HTTP/3 request that appears regular but contains authentication information, within the ongoing transparently forwarded HTTP/3 traffic. This authentication request **MUST NOT** use a fixed `/auth` path or specific XLESS custom headers, but instead **MUST** employ deep obfuscation through the following combined strategies:

### Diversification and Dynamism of Authentication Paths:

  * The client and server **MUST** have a built-in large and continuously updated list of common API paths. This list **SHOULD** include common internet API paths used for user authentication or session management (e.g., `/api/v1/auth`, `/user/login`, `/oauth/token`, `/session/create`, `/api/session`, `/auth/v2/login`, `/web/auth/verify`, etc.).
  * For each authentication attempt, the client **MUST** randomly select a path from this list.
  * After the selected path, the client **MUST** randomly add 2-5 seemingly meaningless but structurally normal query parameters (e.g., `?ts=1704067200&client_id=web_app_xyz&ref=home_page&nonce=random_string`). Parameter names and values **MAY** be randomly combined from a preset list, and the server **MUST** ignore these parameters.

### Obfuscation and Standardization of HTTP Headers:

  * **Standardized Embedding of Authentication Credentials:** XLESS authentication data **MUST** be encapsulated in a format similar to JWT or other common API tokens, and embedded in standard HTTP headers, such as `Authorization: Bearer [XLESS_AUTH_TOKEN]` or `Cookie: session_id=[XLESS_AUTH_TOKEN]; user_token=[MORE_PADDING]`.
  * **Obfuscation of Client Rate:** The actual value of the client's receive rate (`XLESS-CC-RX`) **MUST** be replaced with a more obfuscated custom header, such as `X-Client-Telemetry: {"rx_rate": [uint_val], "timestamp": "..."}` or `X-Device-Capability: {"bandwidth": [uint_val]}`.
  * **Incorporation of Padding Content:** The content of the original `XLESS-Padding` **MUST** be integrated into other variable-length headers, such as `User-Agent` (simulating a specific browser version with appended random strings), `X-Request-ID` (forging a UUID), or a large `X-Custom-Data` header.
  * **Supplementation and Randomization of Common HTTP Headers:** In the authentication request, the client **MUST** randomly add 5-10 common HTTP headers, such as `Accept`, `Accept-Encoding`, `Accept-Language`, `Cache-Control`, `Connection: keep-alive`, `Referer`, `Origin`, `Sec-Fetch-Mode`, etc. The values of these headers **SHOULD** mimic common values from real browsers and **MAY** be randomized in their order. The `User-Agent` header **MUST** always mimic a mainstream browser and its version, and **MAY** randomly add some minor variations.

### Standardization and Randomization of Request Body (Payload):

  * The authentication request body **MUST** use standard formats such as `application/json` or `application/x-www-form-urlencoded`, and the `Content-Type` header **MUST** be correctly set.
  * XLESS authentication data and the actual client receive rate data **MUST** be included as field values within the JSON or form data.
  * In the request body, the client **MUST** randomly add 3-8 meaningless fields (e.g., `random_key_1: "random_value_xyz"`, `padding_data: "long_random_string"`), and **MUST** randomize their order and length. These fields **SHOULD** resemble common additional data found in real web applications.

### Refined Authentication Request Timing and Sequence:

  * Between the completion of simulated Browse and sending the authentication request, the client **MUST** introduce longer, randomly distributed delays to simulate user thinking, clicking, or data entry time after Browse a page.
  * The authentication request **SHOULD NOT** be sent immediately after simulated Browse ends. The client **MAY** randomly insert 1-3 seemingly normal auxiliary requests to the decoy service before or after the authentication request (e.g., requesting an icon, an infrequently loaded JS file, or an API path known to return 404). Responses to these requests **SHOULD** be processed normally by the client.
  * The client **MUST** fully utilize HTTP/3's long connection feature, ensuring that the authentication request occurs over the connection established during previous simulated Browse, avoiding the creation of new connections.

The XLESS server **MUST** identify this obfuscated authentication request and use the encapsulated information to authenticate the client.

### Server Processing of Authentication Requests and Responses:

  * **If authentication is successful:** The server **MUST** immediately stop forwarding all traffic to the decoy service. The server **MUST** return common successful HTTP status codes, such as **200 OK**, **201 Created**, or **204 No Content**, depending on the obfuscated API path and simulated request type. The response body **MAY** be empty or contain randomly padded JSON/text.

    Upon successful authentication, the server **SHOULD** provide the required information in the following response (e.g., embedded in a JSON response body):

    ```json
    {
      // Depending on the obfuscated API path and status code, there may be no specific fields, or random padding.
      "status": "success",
      "data": {
        "udp_support": [true/false],
        "server_rx_rate": [uint_val/"auto"],
        "session_id": "random_uuid_string", // Example, for internal XLESS negotiation or state
        "padding": "random_string" // Padding content, integrated into other fields
      }
    }
    ```

      * **`udp_support`**: Indicates whether the server supports UDP relay.
      * **`server_rx_rate`**: The server's maximum receiving rate in bytes/second. A value of `0` means unlimited; `"auto"` means the server declines to provide a value and requires the client to use congestion control to determine the rate.
      * **`padding`**: A random padding string whose content **SHOULD** be integrated into other variable-length fields.

    For more information on how the `server_rx_rate` value is used, refer to the Congestion Control section.

  * **If authentication fails:** The server **MUST NOT** disconnect the client, nor **MUST** it generate an error status code or error response body itself. The server **MUST** continue to transparently forward this authentication request (as a normal request) to the upstream decoy site and return the decoy site's response to the client. The server **MUST** continue to maintain its transparent forwarding state, allowing the client to continue interacting with the decoy service, and providing an opportunity for subsequent authentication attempts.

The client **MUST** determine whether authentication was successful based on the received HTTP status code and response body content.

Only after the client has authenticated **MUST** the server consider this QUIC connection an XLESS proxy connection. It **MUST** then begin processing proxy requests from the client as described in the next section.

-----

## Proxy Requests

### TCP

For each TCP connection, the client **MUST** create a new QUIC bidirectional stream and send the following `TCPRequest` message:

```
[varint] 0x401 (TCPRequest ID)
[varint] Address length
[bytes] Address string (host:port)
[varint] Padding length
[bytes] Random padding
```

The server **MUST** respond with a `TCPResponse` message:

```
[uint8] Status (0x00 = OK, 0x01 = Error)
[varint] Message length
[bytes] Message string
[varint] Padding length
[bytes] Random padding
```

If the status is `OK`, the server **MUST** then begin forwarding data between the client and the specified TCP address until either party closes the connection. If the status is `Error`, the server **MUST** close the QUIC stream.

### UDP

UDP packets **MUST** be encapsulated in the following `UDPMessage` format and sent via QUIC's unreliable datagrams (both client-to-server and server-to-client):

```
[uint32] Session ID
[uint16] Packet ID
[uint8] Fragment ID
[uint8] Fragment count
[varint] Address length
[bytes] Address string (host:port)
[bytes] Payload
```

The client **MUST** use a unique `Session ID` for each UDP session. The server **SHOULD** allocate a unique UDP port for each `Session ID`, unless it has other mechanisms to distinguish packets from different sessions (e.g., symmetric NAT, different outbound IP addresses, etc.).

This protocol does not provide an explicit way to close a UDP session. While clients **MAY** retain and reuse `Session ID`s indefinitely, servers **SHOULD** release and reallocate the port associated with a `Session ID` after a period of inactivity or if other conditions are met. If a client sends a UDP packet to a `Session ID` that the server no longer recognizes, the server **MUST** treat it as a new session and allocate a new port.

If the server does not support UDP relay, it **SHOULD** silently drop all UDP messages received from the client.

### Fragmentation

Due to the limitations of QUIC's unreliable datagram channel, any UDP packet exceeding the QUIC maximum datagram size **MUST** be fragmented or dropped.

For fragmented packets, each fragment **MUST** carry the same unique `Packet ID`. The `Fragment ID` starts from 0 and indicates the index within the total `Fragment Count`. Both the server and client **MUST** wait for all fragments of a fragmented packet to arrive before processing. If one or more fragments of a packet are lost, the entire packet **MUST** be dropped.

For unfragmented packets, `Fragment Count` **MUST** be set to 1. In this case, the values of `Packet ID` and `Fragment ID` are irrelevant.

-----

## Congestion Control

A unique feature of XLESS is the ability to set send/receive (upload/download) rates on the client. During authentication, the client sends its receive rate to the server via its encapsulated rate information. The server **MAY** use this information to determine its transmission rate to the client, and vice versa, by returning its receive rate to the client.

Three special cases are:

  * If the rate indicated by the client is `0`, it means it does not know its receiving rate. The server **MUST** use a congestion control algorithm (e.g., BBR, Cubic) to adjust its transmission rate.
  * If the rate indicated by the server in its response is `0`, it means it has no bandwidth limits. The client **MAY** transmit at any rate.
  * If the rate indicated by the server in its response is `"auto"`, it means it chooses not to specify a rate. The client **MUST** use a congestion control algorithm to adjust its transmission rate.

-----

## Obfuscation Layers (obfs)

The XLESS protocol supports **optional obfuscation layers**, implemented as `obfs` plugins, which operate on the UDP datagrams carrying QUIC packets. These layers aim to provide diverse traffic fingerprints by transforming the appearance of the QUIC packet payload, while ensuring the outer UDP encapsulation remains standard.

Each `obfs` plugin **MUST** implement an interface that allows it to obfuscate the outgoing QUIC packet (as a UDP payload) and de-obfuscate the incoming UDP payload (to reveal the original QUIC packet). When an `obfs` plugin is enabled, the UDP datagram will carry the transformed QUIC packet, designed to appear as a different, predefined pattern.

The selection of an `obfs` plugin **MAY** be configured by the user. When an `obfs` plugin is used:

* The obfuscated traffic **MUST** remain encapsulated within standard UDP datagrams.
* The chosen `obfs` plugin **SHOULD** transform the QUIC packet payload into a structure that mimics a protocol commonly observed over UDP, such as DNS, NTP, or DTLS. This ensures that the transformed traffic retains a plausible appearance on the network layer.
* The `obfs` plugin **MUST NOT** attempt to mimic protocols that are exclusively or predominantly transmitted over TCP (e.g., HTTP/1.1, HTTP/2, SSH, or conventional TLS handshakes/application data).
* The `obfs` plugin **MUST NOT** alter the fundamental QUIC framing or handshake process, only the appearance of the QUIC packet payload as it travels over UDP.

This approach allows XLESS to achieve a wide range of plausible traffic patterns at the UDP layer, enhancing censorship resistance by diversifying its network footprint.
