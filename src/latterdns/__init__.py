import asyncio
import binascii
import logging
import socket
from contextlib import suppress

import click
import dns.flags
import dns.message

logger: logging.Logger = logging.getLogger(__name__)

MAX_DNS_PACKET: int = 65535


def hex_dump(data: bytes, limit: int = 200) -> str:
    hexed: str = binascii.hexlify(data).decode()
    return hexed[:limit] + "...(truncated)" if len(hexed) > limit else hexed


def log_dns_info(data: bytes, label: str) -> None:
    """Parse packet and log basic DNS info."""
    try:
        parsed: dns.message.Message = dns.message.from_wire(data)
        flags: str = dns.flags.to_text(parsed.flags)
        logger.debug(
            f"{label}: "
            f"ID={parsed.id} FLAGS={flags} OPCODE={parsed.opcode()} "
            f"RCODE={parsed.rcode()} Q={len(parsed.question)} A={len(parsed.answer)} "
            f"AUTH={len(parsed.authority)} ADD={len(parsed.additional)}"
        )
    except Exception:
        logger.error(f"{label}: Failed to parse DNS packet")


async def forward_query_choose_latter(
    query_wire: bytes,
    upstream_host: str,
    upstream_port: int,
    former_timeout: float,
    latter_timeout: float,
) -> bytes | None:
    """Forward DNS query to upstream and choose latter response."""
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        sock.connect((upstream_host, upstream_port))

        loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()

        # Send query
        await loop.sock_sendall(sock, query_wire)
        logger.debug("Query sent to upstream")

        # --- FORMER packet ---
        try:
            former: bytes = await asyncio.wait_for(loop.sock_recv(sock, MAX_DNS_PACKET), timeout=former_timeout)
            logger.debug(f"UPSTREAM-FORMER RAW: {len(former)} bytes HEX={hex_dump(former)}")
            log_dns_info(former, "UPSTREAM-FORMER-PARSED")
        except TimeoutError:
            logger.warning("Upstream former timeout")
            return None
        except Exception as e:
            logger.error(f"Error receiving former packet: {e}")
            return None

        # --- LATTER packet ---
        result: bytes = former
        try:
            latter: bytes = await asyncio.wait_for(loop.sock_recv(sock, MAX_DNS_PACKET), timeout=latter_timeout)
            logger.debug(f"UPSTREAM-LATTER RAW: {len(latter)} bytes HEX={hex_dump(latter)}")
            log_dns_info(latter, "UPSTREAM-LATTER-PARSED")
            logger.info("Upstream latter packet selected")
            result = latter
        except TimeoutError:
            logger.info("Latter timeout — using former response")
        except Exception as e:
            logger.error(f"Error receiving latter packet: {e}")

        return result

    except Exception as e:
        logger.error(f"Error in forward_query_choose_latter: {e}")
        return None
    finally:
        with suppress(Exception):
            sock.close()


async def handle_client_query(
    query_wire: bytes,
    client_addr: tuple[str, int],
    server_sock: socket.socket,
    upstream_config: dict[str, str | int | float],
) -> None:
    """Handle a single client DNS query."""
    logger.info(f"Client query from {client_addr}")
    logger.debug(f"CLIENT RAW: {len(query_wire)} bytes HEX={hex_dump(query_wire)}")
    log_dns_info(query_wire, "CLIENT-PARSED")

    response: bytes | None = await forward_query_choose_latter(
        query_wire,
        str(upstream_config["host"]),
        int(upstream_config["port"]),
        float(upstream_config["former_timeout"]),
        float(upstream_config["latter_timeout"]),
    )

    if response:
        loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
        await loop.sock_sendto(server_sock, response, client_addr)
        logger.info(f"Response sent to {client_addr}")
    else:
        logger.warning(f"No response returned to client {client_addr}")


async def run_dns_latter_choose(
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    former_timeout: float,
    latter_timeout: float,
) -> None:
    """Run the DNS proxy server."""
    server_sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setblocking(False)

    try:
        server_sock.bind(("0.0.0.0", listen_port))  # noqa: S104
        logger.info(f"LatterDNS listening on UDP {listen_port} → upstream {upstream_host}:{upstream_port}")
        logger.info(f"Timeouts: former={former_timeout}s, latter={latter_timeout}s")
    except Exception as e:
        logger.critical(f"Failed to bind UDP port {listen_port}: {e}")
        return

    loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()

    upstream_config: dict[str, str | int | float] = {
        "host": upstream_host,
        "port": upstream_port,
        "former_timeout": former_timeout,
        "latter_timeout": latter_timeout,
    }

    tasks: set[asyncio.Task[None]] = set()

    try:
        while True:
            # Receive query from client
            query_wire: bytes
            client_addr: tuple[str, int]
            query_wire, client_addr = await loop.sock_recvfrom(server_sock, MAX_DNS_PACKET)

            # Handle query in a separate task (allows concurrent processing)
            task: asyncio.Task[None] = asyncio.create_task(
                handle_client_query(
                    query_wire,
                    client_addr,
                    server_sock,
                    upstream_config,
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
    "--former-timeout",
    type=float,
    default=1.0,
    show_default=True,
    help="Timeout for former packet",
)
@click.option(
    "--latter-timeout",
    type=float,
    default=0.5,
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
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    former_timeout: float,
    latter_timeout: float,
    log_level: str,
) -> None:
    """LatterDNS - Returns the latter DNS response packet from upstream."""
    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    asyncio.run(
        run_dns_latter_choose(
            listen_port=listen_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            former_timeout=former_timeout,
            latter_timeout=latter_timeout,
        )
    )
