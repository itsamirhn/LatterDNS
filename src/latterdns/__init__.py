import binascii
import logging
import socket

import click
import dns.flags
import dns.message

logger = logging.getLogger(__name__)

MAX_DNS_PACKET = 65535


def hex_dump(data, limit=200):
    hexed = binascii.hexlify(data).decode()
    return hexed[:limit] + "...(truncated)" if len(hexed) > limit else hexed


def log_dns_info(data, label):
    """Parse packet and log basic DNS info."""
    try:
        parsed = dns.message.from_wire(data)
        flags = dns.flags.to_text(parsed.flags)
        logger.debug(
            f"{label}: "
            f"ID={parsed.id} FLAGS={flags} OPCODE={parsed.opcode()} "
            f"RCODE={parsed.rcode()} Q={len(parsed.question)} A={len(parsed.answer)} "
            f"AUTH={len(parsed.authority)} ADD={len(parsed.additional)}"
        )
    except Exception:
        logger.error(f"{label}: Failed to parse DNS packet")


def forward_query_choose_latter(query_wire, upstream, former_timeout, latter_timeout):
    result = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Connect
        try:
            sock.connect(upstream)
        except Exception as e:
            logger.error(f"Failed to connect to upstream {upstream}: {e}")
            return None  # this is still fine — PLR0911 allows one early abort

        # Send query
        try:
            sock.send(query_wire)
            logger.debug("Query sent to upstream")
        except Exception as e:
            logger.error(f"Failed to send query to upstream: {e}")
            return None

        # --- FORMER packet ---
        sock.settimeout(former_timeout)
        try:
            former = sock.recv(MAX_DNS_PACKET)
            logger.debug(f"UPSTREAM-FORMER RAW: {len(former)} bytes HEX={hex_dump(former)}")
            log_dns_info(former, "UPSTREAM-FORMER-PARSED")
        except TimeoutError:
            logger.warning("Upstream former timeout")
            return None
        except Exception as e:
            logger.error(f"Error receiving former packet: {e}")
            return None

        # --- LATTER packet ---
        sock.settimeout(latter_timeout)
        try:
            latter = sock.recv(MAX_DNS_PACKET)
            logger.debug(f"UPSTREAM-LATTER RAW: {len(latter)} bytes HEX={hex_dump(latter)}")
            log_dns_info(latter, "UPSTREAM-LATTER-PARSED")
            logger.info("Upstream latter packet selected")
            result = latter
        except TimeoutError:
            logger.info("Latter timeout — using former response")
            result = former
        except Exception as e:
            logger.error(f"Error receiving latter packet: {e}")
            result = former

    finally:
        sock.close()

    return result


def run_dns_latter_choose(
    listen_port,
    upstream_host,
    upstream_port,
    former_timeout,
    latter_timeout,
):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind(("0.0.0.0", listen_port))  # noqa: S104
        logger.info(f"LatterDNS listening on UDP {listen_port} → upstream {upstream_host}:{upstream_port}")
    except Exception as e:
        logger.critical(f"Failed to bind UDP port {listen_port}: {e}")
        return

    logger.info(f"Timeouts: former={former_timeout}s, latter={latter_timeout}s")

    upstream = (upstream_host, upstream_port)

    while True:
        query_wire, client_addr = server.recvfrom(MAX_DNS_PACKET)
        logger.info(f"Client query from {client_addr}")
        logger.debug(f"CLIENT RAW: {len(query_wire)} bytes HEX={hex_dump(query_wire)}")
        log_dns_info(query_wire, "CLIENT-PARSED")

        response = forward_query_choose_latter(
            query_wire,
            upstream,
            former_timeout,
            latter_timeout,
        )

        if response:
            server.sendto(response, client_addr)
            logger.info(f"Response sent to {client_addr}")
        else:
            logger.warning(f"No response returned to client {client_addr}")


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
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        case_sensitive=False,
    ),
    default="INFO",
    show_default=True,
    help="Logging level",
)
def main(  # noqa: PLR0913
    listen_port,
    upstream_host,
    upstream_port,
    former_timeout,
    latter_timeout,
    log_level,
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
