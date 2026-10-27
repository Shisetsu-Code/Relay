from __future__ import annotations

import contextlib
import asyncio
import io
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import relay


class LauncherArgumentsTests(unittest.TestCase):
    def assert_invalid(self, arguments: list[str]) -> str:
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
            relay.parse_args(arguments)
        self.assertEqual(error.exception.code, 2)
        return output.getvalue()

    def test_defaults_anchor_data_to_project_and_keep_browser_enabled(self):
        options = relay.parse_args([])
        self.assertEqual(options.proxy_port, 8080)
        self.assertEqual(options.web_port, 8081)
        self.assertEqual(options.reverse_port, 8082)
        self.assertEqual(options.data_dir, Path(relay.__file__).resolve().parent / "data")
        self.assertFalse(options.no_browser)
        self.assertIsNone(options.reverse)

    def test_rejects_invalid_listener_ports(self):
        for flag in ("--proxy-port", "--web-port", "--reverse-port"):
            for value in ("0", "-1", "65536", "abc"):
                with self.subTest(flag=flag, value=value):
                    self.assert_invalid([flag, value])

    def test_rejects_collisions_only_between_active_listeners(self):
        self.assert_invalid(["--web-port", "8080"])
        self.assert_invalid(["--reverse", "https://example.com", "--reverse-port", "8080"])
        self.assert_invalid(["--reverse", "https://example.com", "--reverse-port", "8081"])
        self.assertEqual(relay.parse_args(["--reverse-port", "8080"]).proxy_port, 8080)

    def test_reverse_requires_an_unambiguous_http_origin(self):
        invalid = (
            "example.com",
            "ftp://example.com",
            "https://",
            "https://example.com/path",
            "https://example.com?token=private",
            "https://example.com#private",
            "https://user:private@example.com",
            "https://example.com:0",
            "https://example.com:65536",
            "https://example.com:",
            "https://exa mple.com",
            "https://example.com\n",
            "https://example.com\\@other.example",
            "https://%65xample.com",
            "http://0.0.0.0",
            "http://169.254.169.254",
            "http://metadata.google.internal",
            "http://[fe80::1]",
        )
        for origin in invalid:
            with self.subTest(origin=origin):
                output = self.assert_invalid(["--reverse", origin])
                self.assertNotIn("private", output)

    def test_reverse_supports_provider_origins_and_controlled_loopback(self):
        accepted = {
            "https://GANAMOSONLINE.COM/": "https://ganamosonline.com",
            "https://api.example.com:8443": "https://api.example.com:8443",
            "http://127.0.0.1:9000": "http://127.0.0.1:9000",
            "http://localhost:9000": "http://localhost:9000",
            "https://[::1]:9000/": "https://[::1]:9000",
        }
        for origin, expected in accepted.items():
            with self.subTest(origin=origin):
                self.assertEqual(relay.parse_args(["--reverse", origin]).reverse, expected)

    def test_files_must_exist_but_their_contents_are_not_read_by_argument_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.har"
            self.assert_invalid(["--har", str(path)])
            self.assert_invalid(["--har", directory])
            self.assert_invalid(["--upstream-ca", str(path)])
            path.write_bytes(b"not parsed until the native HAR reader runs")
            options = relay.parse_args(["--har", str(path), "--upstream-ca", str(path)])
            self.assertEqual(options.har, path.resolve())
            self.assertEqual(options.upstream_ca, path.resolve())

    def test_checks_occupied_loopback_ports_before_startup(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            options = relay.parse_args(["--proxy-port", str(port)])
            with self.assertRaisesRegex(ValueError, str(port)):
                relay.check_listen_ports(options)

    def test_runtime_requires_the_audited_engine_version(self):
        with mock.patch("relay.importlib.metadata.version", return_value="12.3.0"):
            with self.assertRaisesRegex(RuntimeError, "12.3.1"):
                relay.check_runtime()


class SessionTests(unittest.TestCase):
    def test_each_session_has_private_distinct_capture_and_report_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            first = relay.create_session(data_dir)
            second = relay.create_session(data_dir)
            self.assertNotEqual(first.session_dir, second.session_dir)
            self.assertEqual(first.ca_dir, data_dir / "ca")
            self.assertEqual(first.session_dir.parent, data_dir / "sessions")
            self.assertRegex(first.session_dir.name, r"^\d{8}T\d{6}\.\d{6}Z-[0-9a-f]+$")
            self.assertEqual(first.capture_path, first.session_dir / "traffic.mitm")
            self.assertEqual(first.report_path, first.session_dir / "audit.jsonl")
            self.assertTrue(first.capture_path.is_file())
            self.assertTrue(first.report_path.is_file())
            if os.name != "nt":
                self.assertEqual(first.session_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(first.capture_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(first.report_path.stat().st_mode & 0o777, 0o600)


class EngineConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.master = None

    async def asyncTearDown(self):
        if self.master is not None:
            await self.master.done()

    async def configure(self, *arguments: str):
        args = relay.parse_args(["--data-dir", str(self.root / "data"), "--no-browser", *arguments])
        paths = relay.create_session(args.data_dir)
        self.master = relay.configure_master(args, paths)
        # mitmproxy's native script watcher registers addon options asynchronously.
        await asyncio.sleep(0.01)
        return args, paths, self.master.options

    async def test_native_configuration_is_local_passive_and_authenticated(self):
        args, paths, options = await self.configure("--reverse", "https://ganamosonline.com")
        self.assertEqual(options.listen_host, "127.0.0.1")
        self.assertEqual(options.web_host, "127.0.0.1")
        self.assertEqual(options.listen_port, 8080)
        self.assertEqual(options.web_port, 8081)
        self.assertEqual(options.mode, ["regular@127.0.0.1:8080", "reverse:https://ganamosonline.com@127.0.0.1:8082"])
        self.assertEqual(options.confdir, str(paths.ca_dir))
        self.assertFalse(options.web_open_browser)
        self.assertFalse(options.anticache)
        self.assertFalse(options.anticomp)
        self.assertFalse(options.ssl_insecure)
        self.assertEqual(options.client_replay, [])
        self.assertEqual(options.server_replay, [])
        self.assertEqual(options.modify_headers, [])
        self.assertEqual(options.modify_body, [])
        self.assertEqual(options.map_remote, [])
        self.assertEqual(options.map_local, [])
        self.assertEqual(options.scripts, [str(Path(relay.__file__).resolve().parent / "relay_inspector" / "addon.py")])
        self.assertEqual(options.relay_report_path, str(paths.report_path))
        self.assertEqual(options.web_password, "")
        token = parse_qs(urlsplit(self.master.web_url).query)["token"][0]
        self.assertGreaterEqual(len(token), 32)
        auth = self.master.addons.get("webauth")
        self.assertTrue(auth.is_valid_password(token))
        self.assertFalse(auth.is_valid_password(""))

    async def test_neither_local_ca_config_nor_home_config_is_loaded(self):
        data_dir = self.root / "data"
        ca_dir = data_dir / "ca"
        ca_dir.mkdir(parents=True)
        marker = self.root / "configuration-executed"
        script = self.root / "inherited_script.py"
        script.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
        inherited_config = (
            f"scripts: [{str(script)!r}]\n"
            "listen_host: 0.0.0.0\nweb_host: 0.0.0.0\nssl_insecure: true\n"
            "anticache: true\nanticomp: true\n"
            "client_replay: [does-not-exist.mitm]\nserver_replay: [does-not-exist.mitm]\n"
            "modify_headers: ['/^/X-Injected/yes']\nweb_password: fixed-inherited-password\n"
        )
        (ca_dir / "config.yaml").write_text(inherited_config, encoding="utf-8")
        (ca_dir / "config.yml").write_text("invalid: [yaml", encoding="utf-8")
        home = self.root / "home"
        (home / ".mitmproxy").mkdir(parents=True)
        (home / ".mitmproxy" / "config.yaml").write_text(inherited_config, encoding="utf-8")
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)}), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            _, _, options = await self.configure()
        self.assertFalse(marker.exists())
        self.assertEqual(options.client_replay, [])
        self.assertEqual(options.server_replay, [])
        self.assertEqual(options.modify_headers, [])
        self.assertEqual(options.web_host, "127.0.0.1")
        self.assertEqual(options.web_password, "")
        self.assertFalse(options.ssl_insecure)
        self.assertEqual(output.getvalue(), "")

    async def test_initial_har_is_inspection_only(self):
        har = self.root / "sensitive.har"
        har.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        _, _, options = await self.configure("--har", str(har))
        self.assertEqual(options.rfile, str(har))
        self.assertEqual(options.client_replay, [])
        self.assertEqual(options.server_replay, [])

    async def test_custom_upstream_ca_keeps_tls_verification_enabled(self):
        ca = self.root / "upstream-ca.pem"
        ca.write_bytes(b"loaded when a TLS connection is made")
        _, _, options = await self.configure("--upstream-ca", str(ca))
        self.assertEqual(options.ssl_verify_upstream_trusted_ca, str(ca))
        self.assertFalse(options.ssl_insecure)

    async def test_percent_characters_in_data_directory_are_not_strftime_templates(self):
        data_dir = self.root / "literal-%Y-directory"
        args = relay.parse_args(["--data-dir", str(data_dir), "--no-browser"])
        paths = relay.create_session(args.data_dir)
        self.master = relay.configure_master(args, paths)
        saver = self.master.addons.get("save")
        self.assertEqual(saver.current_path, str(paths.capture_path))
        self.assertTrue(paths.capture_path.is_file())


if __name__ == "__main__":
    unittest.main()
