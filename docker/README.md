icgood/proxy-protocol
=====================

Docker image that proxies host ports to swarm services with [PROXY protocol][1]
headers, using [`proxyprotocol-server`][2].

The intention is to bind to host ports and proxy connections to Docker's
built-in load balancers. The services should expect a PROXY protocol header.

## Usage

First, create a new service in your `docker-compose.yml`:

```yaml
  proxy:
    image: icgood/proxy-protocol
    deploy:
      mode: global
```

The `mode: global` configuration means the service will run a single instance
on each node.

Declare one or more host port bindings:

```yaml
    ports:
      - target: 143
        published: 143
        protocol: tcp
        mode: host
      - target: 4190
        published: 4190
        protocol: tcp
        mode: host
```

Finally, modify the service endpoint to proxy the ports to a backend service:

```yaml
    entrypoint: >-
      proxyprotocol-server
        --service :143 imap-server:143
        --service :4190 imap-server:4190
```

In the above example, another service named `imap-server` should be listening
on ports *143* and *4190*.

[1]: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
[2]: https://github.com/icgood/proxy-protocol