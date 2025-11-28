#!/usr/bin/env python3
import socket
import logging
import binascii
import click
import dns.message
import dns.flags

MAX_DNS_PACKET = 65535


def hex_dump(data, limit=200):
    hexed = binascii.hexlify(data).decode()
    return hexed[:limit] + "...(truncated)" if len(hexed) > limit else hexed


def log_dns_info(data, label):
    """Parse packet and log basic DNS info."""
    try:
        parsed = dns.message.from_wire(data)
        flags = dns.flags.to_text(parsed.flags)
        logging.info(
            f"{label}: ID={parsed.id} FLAGS={flags} OPCODE={parsed.opcode()} "
            f"RCODE={parsed.rcode()} Q={len(parsed.question)} A={len(parsed.answer)} "
            f"AUTH={len(parsed.authority)} ADD={len(parsed.additional)}"
        )
    except Exception:
        logging.info(f"{label}: Could not parse DNS packet")


def forward_query_choose_latter(query_wire, upstream, former_timeout, latter_timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Connect to upstream to ensure we only receive from this specific server
    sock.connect(upstream)

    # Send query upstream
    sock.send(query_wire)

    # --- FORMER packet ---
    sock.settimeout(former_timeout)
    try:
        former = sock.recv(MAX_DNS_PACKET)
        logging.info(f"UPSTREAM-FORMER: {len(former)} bytes HEX={hex_dump(former)}")
        log_dns_info(former, "UPSTREAM-FORMER-PARSED")
    except socket.timeout:
        logging.warning("No upstream response (former timeout)")
        sock.close()
        return None

    # --- LATTER packet ---
    sock.settimeout(latter_timeout)
    try:
        latter = sock.recv(MAX_DNS_PACKET)
        logging.info(f"UPSTREAM-LATTER: {len(latter)} bytes HEX={hex_dump(latter)}")
        log_dns_info(latter, "UPSTREAM-LATTER-PARSED")
        sock.close()
        return latter
    except socket.timeout:
        sock.close()
        return former


def run_dns_latter_choose(
    listen_port, upstream_host, upstream_port, former_timeout, latter_timeout
):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", listen_port))

    upstream = (upstream_host, upstream_port)
    logging.info(
        f"DNS Latter Choose Proxy running on UDP {listen_port} → upstream {upstream_host}:{upstream_port}"
    )
    logging.info(f"Timeouts: former={former_timeout}s latter={latter_timeout}s")

    while True:
        query_wire, client_addr = server.recvfrom(MAX_DNS_PACKET)
        logging.info(
            f"CLIENT: {client_addr} {len(query_wire)} bytes HEX={hex_dump(query_wire)}"
        )
        log_dns_info(query_wire, "CLIENT-PARSED")

        response = forward_query_choose_latter(
            query_wire, upstream, former_timeout, latter_timeout
        )

        if response:
            server.sendto(response, client_addr)
            logging.info(f"Sent response to {client_addr}")
        else:
            logging.info("No response returned to client")


@click.command()
@click.option(
    "--listen-port",
    type=int,
    default=1053,
    show_default=True,
    help="Port to listen on",
)
@click.option(
    "--upstream-host",
    type=str,
    default="1.1.1.1",
    show_default=True,
    help="Upstream DNS host",
)
@click.option(
    "--upstream-port",
    type=int,
    default=53,
    show_default=True,
    help="Upstream DNS port",
)
@click.option(
    "--former-timeout",
    type=float,
    default=1.0,
    show_default=True,
    help="Timeout for former packet",
)
@click.option(
    "--latter-timeout",
    type=float,
    default=0.1,
    show_default=True,
    help="Timeout for latter packet",
)
@click.option(
    "--log-level",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
    default="INFO",
    show_default=True,
    help="Logging level",
)
def main(
    listen_port, upstream_host, upstream_port, former_timeout, latter_timeout, log_level
):
    """LatterDNS - Returns the latter DNS response packet from upstream."""
    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    run_dns_latter_choose(
        listen_port=listen_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        former_timeout=former_timeout,
        latter_timeout=latter_timeout,
    )


if __name__ == "__main__":
    main()
