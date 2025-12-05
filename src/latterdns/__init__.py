import asyncio
import binascii
import logging
import socket
from contextlib import suppress

import click

logger = logging.getLogger(__name__)

MAX_DNS_PACKET = 65535


def hex_dump(data, limit=200):
    hexed = binascii.hexlify(data).decode()
    return hexed[:limit] + "...(truncated)" if len(hexed) > limit else hexed


async def forward_query_choose_latter(
    query_wire,
    upstream_addr,
    timeouts,
):
    """Forward DNS query to upstream and wait for multiple packets with individual timeouts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        sock.connect(upstream_addr)

        loop = asyncio.get_event_loop()

        # Send query
        await loop.sock_sendall(sock, query_wire)
        logger.debug("Query sent to upstream")

        packets = []

        for i, timeout_ms in enumerate(timeouts, start=1):
            timeout_s = timeout_ms / 1000.0
            try:
                packet = await asyncio.wait_for(loop.sock_recv(sock, MAX_DNS_PACKET), timeout=timeout_s)
                logger.debug(f"Packet {i} received: {len(packet)} bytes HEX={hex_dump(packet)}")
                packets.append(packet)
            except TimeoutError:
                logger.info(f"Packet {i} timeout after {timeout_ms}ms, returning last received packet")
                break
            except Exception as e:
                logger.error(f"Packet {i} receive error: {e}")
                break

        if packets:
            logger.info(f"Returning packet {len(packets)} of {len(timeouts)}")
            return packets[-1]
        logger.warning("No packets received")
        return None

    except Exception as e:
        logger.error(f"Upstream query error: {e}")
        return None
    finally:
        with suppress(Exception):
            sock.close()


async def handle_client_query(
    query_wire,
    client_addr,
    server_sock,
    upstream_addr,
    timeouts,
):
    """Handle a single client DNS query."""
    logger.info(f"Query received from {client_addr}")
    logger.debug(f"Query packet: {len(query_wire)} bytes HEX={hex_dump(query_wire)}")

    response = await forward_query_choose_latter(
        query_wire,
        upstream_addr,
        timeouts,
    )

    if response:
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(server_sock, response, client_addr)
        logger.info(f"Response sent to {client_addr}")
    else:
        logger.warning(f"No response available for {client_addr}")


async def run_dns_latter_choose(
    *,
    listen_addr,
    upstream_addr,
    timeouts,
):
    """Run the DNS proxy server."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setblocking(False)

    listen_host, listen_port = listen_addr
    upstream_host, upstream_port = upstream_addr

    try:
        server_sock.bind(listen_addr)
        logger.info(
            f"MultiPacketDNS listening on {listen_host}:{listen_port} → upstream {upstream_host}:{upstream_port}"
        )
        logger.info(f"Timeouts (milliseconds): {timeouts}")
    except Exception as e:
        logger.critical(f"Failed to bind {listen_host}:{listen_port}: {e}")
        return

    loop = asyncio.get_event_loop()

    tasks = set()

    try:
        while True:
            # Receive query from client
            query_wire, client_addr = await loop.sock_recvfrom(server_sock, MAX_DNS_PACKET)

            # Handle query in a separate task (allows concurrent processing)
            task = asyncio.create_task(
                handle_client_query(
                    query_wire,
                    client_addr,
                    server_sock,
                    upstream_addr,
                    timeouts,
                )
            )
            tasks.add(task)
            task.add_done_callback(tasks.discard)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        server_sock.close()
        # Cancel remaining tasks
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


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
    "--timeouts",
    type=int,
    multiple=True,
    default=[100, 500],
    show_default=True,
    help="Timeout values in milliseconds (can be specified multiple times, e.g., --timeouts 100 --timeouts 500)",
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
def main(
    listen_port,
    upstream_host,
    upstream_port,
    timeouts,
    log_level,
):
    """LatterDNS - Returns the latter DNS response packet from upstream."""
    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if not timeouts:
        raise click.BadParameter("At least one timeout value is required")
    if any(t <= 0 for t in timeouts):
        raise click.BadParameter("All timeout values must be positive")

    asyncio.run(
        run_dns_latter_choose(
            listen_addr=("0.0.0.0", listen_port),  # noqa: S104
            upstream_addr=(upstream_host, upstream_port),
            timeouts=list(timeouts),
        )
    )
