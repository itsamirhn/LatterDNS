#!/usr/bin/env python3
import socket
import logging
import binascii
import argparse
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

    # Send query upstream
    sock.sendto(query_wire, upstream)

    # --- FORMER packet ---
    sock.settimeout(former_timeout)
    try:
        former, addr = sock.recvfrom(MAX_DNS_PACKET)
        logging.info(f"UPSTREAM-FORMER: {len(former)} bytes HEX={hex_dump(former)}")
        log_dns_info(former, "UPSTREAM-FORMER-PARSED")
    except socket.timeout:
        logging.warning("No upstream response (former timeout)")
        sock.close()
        return None

    # --- LATTER packet ---
    sock.settimeout(latter_timeout)
    try:
        latter, addr = sock.recvfrom(MAX_DNS_PACKET)
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


def main():
    parser = argparse.ArgumentParser(description="DNS Latter Choose Proxy")
    parser.add_argument(
        "--listen-port", type=int, default=1053, help="Port to listen on"
    )
    parser.add_argument(
        "--upstream-host", type=str, default="1.1.1.1", help="Upstream DNS host"
    )
    parser.add_argument(
        "--upstream-port", type=int, default=53, help="Upstream DNS port"
    )
    parser.add_argument(
        "--former-timeout", type=float, default=1.0, help="Timeout for former packet"
    )
    parser.add_argument(
        "--latter-timeout", type=float, default=0.1, help="Timeout for latter packet"
    )
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    run_dns_latter_choose(
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        former_timeout=args.former_timeout,
        latter_timeout=args.latter_timeout,
    )


if __name__ == "__main__":
    main()
