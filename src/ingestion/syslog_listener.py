"""Syslog UDP listener on port 514.

Receives syslog messages from firewalls, routers, IDS/IPS, and other
network devices. Parses RFC 3164 and RFC 5424 formats.
"""

import asyncio
import json
import re
import uuid
from datetime import datetime

import structlog

logger = structlog.get_logger()


class SyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol handler for syslog messages."""

    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("syslog_listener_started", port=514)

    def datagram_received(self, data: bytes, addr: tuple):
        """Process incoming syslog UDP datagram."""
        try:
            message = data.decode("utf-8", errors="replace").strip()
            parsed = self._parse_syslog_message(message, addr)

            # Fire async callback to process the alert
            asyncio.ensure_future(self.alert_callback(parsed))

        except Exception as e:
            logger.error("syslog_parse_error", error=str(e), addr=addr)

    def _parse_syslog_message(self, message: str, addr: tuple) -> dict:
        """Parse syslog message into structured dict."""
        result = {
            "id": str(uuid.uuid4()),
            "source": "syslog",
            "received_at": datetime.utcnow().isoformat(),
            "sender_ip": addr[0],
            "sender_port": addr[1],
        }

        # Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME ...
        match_5424 = re.match(
            r"<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)",
            message,
        )
        if match_5424:
            pri = int(match_5424.group(1))
            result.update({
                "format": "rfc5424",
                "priority": pri,
                "severity": pri % 8,
                "facility": pri // 8,
                "version": match_5424.group(2),
                "timestamp": match_5424.group(3),
                "hostname": match_5424.group(4),
                "app_name": match_5424.group(5),
                "proc_id": match_5424.group(6),
                "msg_id": match_5424.group(7),
                "message": match_5424.group(8),
            })
            return result

        # Try RFC 3164: <PRI>TIMESTAMP HOSTNAME MESSAGE
        match_3164 = re.match(
            r"<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)",
            message,
        )
        if match_3164:
            pri = int(match_3164.group(1))
            result.update({
                "format": "rfc3164",
                "priority": pri,
                "severity": pri % 8,
                "facility": pri // 8,
                "timestamp": match_3164.group(2),
                "hostname": match_3164.group(3),
                "message": match_3164.group(4),
            })
            return result

        # Fallback: raw message
        result.update({
            "format": "raw",
            "message": message,
            "hostname": addr[0],
        })
        return result


async def start_syslog_listener(alert_callback, host: str = "0.0.0.0", port: int = 514):
    """Start the async syslog UDP listener."""
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(alert_callback),
        local_addr=(host, port),
    )
    logger.info("syslog_listener_ready", host=host, port=port)
    return transport