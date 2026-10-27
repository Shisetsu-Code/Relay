#!/usr/bin/env python3
"""Launch the pinned mitmweb engine with local, isolated Relay settings.

The normal mitmweb CLI reads config.yaml/config.yml before applying all command
line arguments. Relay deliberately uses WebMaster without that configuration
loader: a saved replay or script must never run just because a HAR is opened.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.metadata
import ipaddress
import logging
from pathlib import Path
import re
import secrets
import signal
import socket
import sys
from typing import Sequence
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent
MITMPROXY_VERSION = "12.3.1"
LOOPBACK = "127.0.0.1"


@dataclass(frozen=True)
class SessionPaths:
    data_dir: Path
    ca_dir: Path
    session_dir: Path
    capture_path: Path
    report_path: Path


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("el puerto debe ser un entero entre 1 y 65535") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("el puerto debe estar entre 1 y 65535")
    return port


def _existing_file(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError("el archivo indicado no existe o no es un archivo regular")
    return path


def _reverse_origin(value: str) -> str:
    """Accept one HTTP(S) origin, never credentials or a request URL.

    Loopback origins are useful for controlled tests. Link-local/metadata,
    multicast and unspecified literal addresses are not upstream origins.
    This is input validation, not a DNS-based network access policy.
    """
    message = "usa un origen http:// o https:// con host y puerto opcional, sin credenciales, ruta, query ni fragmento"
    try:
        if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError
        if "\\" in value:
            raise ValueError
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError
        # Empty delimiters are still request-URL components, not an origin.
        if "?" in value or "#" in value or parsed.netloc.endswith(":"):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if "%" in host:
            raise ValueError

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = host.encode("idna").decode("ascii").lower().rstrip(".")
            labels = host.split(".")
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError
            # Reject legacy numeric IPv4 spellings, which DNS/socket APIs may
            # reinterpret differently from Python's strict IP parser.
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host):
                raise ValueError
            if host in {"metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}:
                raise ValueError
        else:
            checked = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
            if checked.is_unspecified or checked.is_multicast or checked.is_link_local:
                raise ValueError
            host = f"[{address.compressed}]" if address.version == 6 else str(address)

        return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")
    except (ValueError, UnicodeError):
        # Do not echo an invalid URL: it may contain a password or HAR token.
        raise argparse.ArgumentTypeError(message) from None


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Relay: proxy local HTTP/HTTPS e inspector de HAR con mitmweb.",
        epilog=(
            f"Requiere Python 3.12+ y mitmproxy=={MITMPROXY_VERSION}. "
            "Importar un HAR no reenvía solicitudes. La interfaz usa un token "
            "aleatorio nativo. La CA queda en data/ca y cada captura en "
            "data/sessions/<UTC-aleatorio>/. No se cargan config.yaml/config.yml "
            "de mitmproxy. El motor conserva su límite nativo de subida web de 4 GiB."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--har", type=_existing_file, metavar="ARCHIVO", help="cargar un HAR para inspección; no activa replay")
    parser.add_argument("--data-dir", type=Path, default=PROJECT_ROOT / "data", metavar="DIR", help="directorio de CA y sesiones (predeterminado: data junto a relay.py)")
    parser.add_argument("--proxy-port", type=_port, default=8080, metavar="PUERTO", help="puerto del proxy del navegador en 127.0.0.1 (8080)")
    parser.add_argument("--web-port", type=_port, default=8081, metavar="PUERTO", help="puerto de la interfaz en 127.0.0.1 (8081)")
    parser.add_argument("--no-browser", action="store_true", help="mostrar el enlace local sin abrir el navegador")
    parser.add_argument("--reverse", type=_reverse_origin, metavar="ORIGEN", help="añadir un proxy inverso fijo, por ejemplo https://ganamosonline.com")
    parser.add_argument("--reverse-port", type=_port, default=8082, metavar="PUERTO", help="puerto loopback del proxy inverso adicional (8082)")
    parser.add_argument("--upstream-ca", type=_existing_file, metavar="PEM", help="CA PEM de un upstream privado; mantiene la validación TLS")
    args = parser.parse_args(argv)
    ports = [args.proxy_port, args.web_port]
    if args.reverse:
        ports.append(args.reverse_port)
    if len(ports) != len(set(ports)):
        parser.error("los puertos de los listeners activos deben ser distintos")
    args.data_dir = args.data_dir.expanduser().resolve()
    return args


def check_runtime() -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError("Relay requiere Python 3.12 o posterior")
    try:
        installed = importlib.metadata.version("mitmproxy")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("faltan las dependencias: ejecuta python -m pip install -r requirements.txt") from None
    if installed != MITMPROXY_VERSION:
        raise RuntimeError(f"Relay requiere mitmproxy=={MITMPROXY_VERSION}; instala requirements.txt en el entorno activo")


def check_listen_ports(args: argparse.Namespace) -> None:
    """Give a useful early error; the engine still performs the final binds."""
    ports = [args.proxy_port, args.web_port]
    if args.reverse:
        ports.append(args.reverse_port)
    sockets: list[socket.socket] = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(listener)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                listener.bind((LOOPBACK, port))
            except OSError:
                raise ValueError(f"el puerto local {port} está ocupado o no se puede usar; elige otro puerto") from None
    finally:
        for listener in sockets:
            listener.close()


def create_session(data_dir: Path) -> SessionPaths:
    data_dir = data_dir.expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_dir = data_dir / "ca"
    ca_dir.mkdir(exist_ok=True, mode=0o700)
    sessions = data_dir / "sessions"
    sessions.mkdir(exist_ok=True, mode=0o700)
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + secrets.token_hex(6)
    session_dir = sessions / name
    session_dir.mkdir(mode=0o700)
    capture_path = session_dir / "traffic.mitm"
    report_path = session_dir / "audit.jsonl"
    capture_path.touch(mode=0o600, exist_ok=False)
    report_path.touch(mode=0o600, exist_ok=False)
    return SessionPaths(data_dir, ca_dir, session_dir, capture_path, report_path)


def build_mitmweb_args(args: argparse.Namespace, paths: SessionPaths) -> list[str]:
    arguments = [
        "--mode", f"regular@{LOOPBACK}:{args.proxy_port}",
        "--listen-host", LOOPBACK,
        "--listen-port", str(args.proxy_port),
        "--web-host", LOOPBACK,
        "--web-port", str(args.web_port),
        "-s", str(PROJECT_ROOT / "relay_inspector" / "addon.py"),
        "-w", str(paths.capture_path).replace("%", "%%"),
    ]
    settings = {
        "confdir": str(paths.ca_dir),
        "web_open_browser": str(not args.no_browser).lower(),
        "anticache": "false",
        "anticomp": "false",
        "ssl_insecure": "false",
        "command_history": "false",
        "relay_report_path": str(paths.report_path),
    }
    for name, value in settings.items():
        arguments.extend(["--set", f"{name}={value}"])
    if args.har:
        arguments.extend(["-r", str(args.har)])
    if args.reverse:
        arguments.extend(["--mode", f"reverse:{args.reverse}@{LOOPBACK}:{args.reverse_port}"])
    if args.upstream_ca:
        arguments.extend(["--set", f"ssl_verify_upstream_trusted_ca={args.upstream_ca}"])
    return arguments


def configure_master(args: argparse.Namespace, paths: SessionPaths):
    """Configure WebMaster in an active event loop, without opening listeners.

    The native script loader registers the passive addon's deferred options on
    the next event-loop turns. No saved configuration is read at any point.
    """
    check_runtime()
    from mitmproxy.options import Options
    from mitmproxy.tools import cmdline
    from mitmproxy.tools.main import process_options
    from mitmproxy.tools.web.master import WebMaster
    from relay_inspector.har_import import install_har_reader

    install_har_reader()
    options = Options(confdir=str(paths.ca_dir), listen_host=LOOPBACK)
    # Console output is limited to our own startup notice. Native engine events
    # remain available in mitmweb, where URLs/bodies belong; never dump HAR URLs
    # or exception payloads to a terminal log.
    master = WebMaster(options, with_termlog=False)
    parser = cmdline.mitmweb(options)
    engine_args = parser.parse_args(build_mitmweb_args(args, paths))
    options.set(*engine_args.setoptions, defer=True)
    process_options(parser, options, engine_args)
    return master


class _StartupNotice:
    def __init__(self, master, args: argparse.Namespace, paths: SessionPaths):
        self.master = master
        self.args = args
        self.paths = paths

    def running(self):
        print(f"Proxy del navegador: http://{LOOPBACK}:{self.args.proxy_port}", flush=True)
        if self.args.reverse:
            print(f"Proxy inverso local: http://{LOOPBACK}:{self.args.reverse_port}", flush=True)
        print(f"Interfaz local (token de esta sesión): {self.master.web_url}", flush=True)
        print(f"Captura: {self.paths.capture_path}", flush=True)


async def run_mitmweb(args: argparse.Namespace, paths: SessionPaths) -> None:
    logging.getLogger().setLevel(logging.INFO)
    for logger_name in ("tornado", "asyncio", "hpack", "quic"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    master = configure_master(args, paths)
    master.addons.add(_StartupNotice(master, args, paths))
    loop = asyncio.get_running_loop()
    previous_handlers = {}
    installed_on_loop = set()
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            try:
                loop.add_signal_handler(signum, master.shutdown)
                installed_on_loop.add(signum)
            except NotImplementedError:
                # Windows ProactorEventLoop does not implement signal handlers.
                signal.signal(signum, lambda *_: master.shutdown())
        if hasattr(signal, "SIGPIPE"):
            previous_handlers[signal.SIGPIPE] = signal.getsignal(signal.SIGPIPE)
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        await master.run()
    finally:
        for signum, previous in previous_handlers.items():
            if signum in installed_on_loop:
                loop.remove_signal_handler(signum)
            signal.signal(signum, previous)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        check_runtime()
        check_listen_ports(args)
        paths = create_session(args.data_dir)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Relay: {error}", file=sys.stderr)
        return 1
    try:
        asyncio.run(run_mitmweb(args, paths))
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Exceptions from malformed imported payloads may contain secrets. Keep
        # details in the native GUI event log, not in a captured console log.
        print(f"Relay no pudo iniciar o continuar ({type(error).__name__}). Comprueba los puertos y los archivos locales.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
