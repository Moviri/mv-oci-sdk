import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, Mock, patch

import pytest
import urllib3
from urllib3.exceptions import HeaderParsingError, ProtocolError

from oci import constants, exceptions
from oci._vendor import requests
from oci.base_client import (
    BaseClient,
    OCIConnectionPool,
    OCIHTTPAdapter,
    OCIPoolManager,
    OCIProxyManager,
)
from oci.object_storage.transfer.upload_manager import UploadManager
from oci.request import Request


class RequestBodyRecorder(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                chunk_size = int(self.rfile.readline().strip(), 16)
                if chunk_size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(chunk_size))
                self.rfile.read(2)
            body = b"".join(chunks)
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))

        self.server.received_requests.append(
            {
                "body": body,
                "transfer_encoding": self.headers.get("Transfer-Encoding"),
                "content_length": self.headers.get("Content-Length"),
            }
        )
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


def valid_config():
    return {
        "tenancy": "ocid1.tenancy.oc1..aaaa",
        "user": "ocid1.user.oc1..aaaa",
        "fingerprint": ":".join(["aa"] * 16),
        "key_file": "/tmp/mv-oci-sdk-test-key.pem",
        "region": "us-phoenix-1",
    }


def make_client():
    return BaseClient(
        "test",
        valid_config(),
        Mock(),
        {},
        service_endpoint="https://example.com",
    )


def successful_response():
    response = Mock()
    response.status_code = 200
    response.headers = {}
    response.content = b""
    response.elapsed = 0
    return response


def sdk_request(url="https://example.com/resource"):
    return Request(
        "GET",
        url,
        header_params={constants.HEADER_REQUEST_ID: "request-id"},
    )


def test_import_and_client_creation_do_not_mutate_global_pool_mapping():
    code = """
import urllib3
before = urllib3.poolmanager.pool_classes_by_scheme.copy()
from unittest.mock import Mock
from oci.base_client import BaseClient
config = {
    "tenancy": "ocid1.tenancy.oc1..aaaa",
    "user": "ocid1.user.oc1..aaaa",
    "fingerprint": ":".join(["aa"] * 16),
    "key_file": "/tmp/mv-oci-sdk-test-key.pem",
    "region": "us-phoenix-1",
}
BaseClient("test", config, Mock(), {}, service_endpoint="https://example.com")
after = urllib3.poolmanager.pool_classes_by_scheme
assert before == after
assert before["https"] is after["https"]
"""
    subprocess.run([sys.executable, "-c", code], check=True)


def test_oci_adapter_builds_scoped_direct_and_proxy_pools():
    global_mapping = urllib3.poolmanager.pool_classes_by_scheme.copy()
    adapter = OCIHTTPAdapter()

    assert isinstance(adapter.poolmanager, OCIPoolManager)
    assert isinstance(
        adapter.poolmanager.connection_from_url("https://example.com"),
        OCIConnectionPool,
    )

    proxy_manager = adapter.proxy_manager_for("http://proxy.example:8080")
    assert isinstance(proxy_manager, OCIProxyManager)
    assert isinstance(
        proxy_manager.connection_from_url("https://example.com"),
        OCIConnectionPool,
    )
    assert urllib3.poolmanager.pool_classes_by_scheme == global_mapping


def test_socks_proxy_delegates_to_requests_adapter():
    adapter = OCIHTTPAdapter()
    sentinel = object()
    with patch.object(
        requests.adapters.HTTPAdapter,
        "proxy_manager_for",
        return_value=sentinel,
    ) as parent_proxy_manager:
        assert adapter.proxy_manager_for("socks5://proxy.example:1080") is sentinel

    parent_proxy_manager.assert_called_once()


def test_generator_body_uses_urllib3_chunked_request_path():
    assert urllib3.__version__.split(".", 1)[0] == "2"
    server = ThreadingHTTPServer(("127.0.0.1", 0), RequestBodyRecorder)
    server.received_requests = []
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    session = requests.Session()

    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/upload"
        chunked_response = session.post(
            endpoint,
            data=(chunk for chunk in (b"first-", b"second-", b"third")),
            timeout=(2, 2),
        )
        fixed_response = session.post(
            endpoint,
            data=b"fixed-length",
            timeout=(2, 2),
        )
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert chunked_response.status_code == 200
    assert fixed_response.status_code == 200
    assert server.received_requests[0] == {
        "body": b"first-second-third",
        "transfer_encoding": "chunked",
        "content_length": None,
    }
    assert server.received_requests[1] == {
        "body": b"fixed-length",
        "transfer_encoding": None,
        "content_length": str(len(b"fixed-length")),
    }


def test_adapter_translates_urllib3_protocol_errors():
    adapter = requests.adapters.HTTPAdapter()
    prepared_request = requests.Request(
        "POST",
        "https://example.com/upload",
        data=(chunk for chunk in (b"one", b"two")),
    ).prepare()
    connection = Mock()
    connection.urlopen.side_effect = ProtocolError("transport failed")

    with (
        patch.object(adapter, "get_connection", return_value=connection),
        patch.object(adapter, "cert_verify"),
    ):
        with pytest.raises(requests.exceptions.ConnectionError):
            adapter.send(prepared_request)


def test_object_storage_pool_resize_preserves_oci_adapter():
    current = OCIHTTPAdapter(pool_connections=7, pool_maxsize=10, pool_block=True)
    resized = UploadManager._create_adapter_for_pool_size(current, 32)

    assert isinstance(resized, OCIHTTPAdapter)
    assert resized._pool_connections == 7
    assert resized._pool_maxsize == 32
    assert resized._pool_block is True


def test_header_parsing_error_recovers_after_one_session_reset(monkeypatch):
    client = make_client()
    old_session = MagicMock()
    new_session = MagicMock()
    old_session.request.side_effect = HeaderParsingError(
        ["Authorization: Bearer first-secret"],
        b"",
    )
    new_session.request.return_value = successful_response()
    client.session = old_session
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))

    response = client.request(sdk_request())

    assert response.status == 200
    assert client.session is new_session
    old_session.close.assert_called_once_with()
    new_session.request.assert_called_once()


def test_header_parsing_error_exhaustion_is_bounded_and_redacted(monkeypatch):
    client = make_client()
    sessions = [MagicMock(), MagicMock(), MagicMock()]
    for session in sessions:
        session.request.side_effect = HeaderParsingError(
            ["Proxy-Authorization: Basic cHJveHk6c2VjcmV0"],
            b"",
        )
    client.session = sessions[0]
    monkeypatch.setenv("OCI_HEADER_PARSING_ERROR_MAX_RETRIES", "1")
    monkeypatch.setattr(
        "oci.base_client.copy.copy",
        Mock(side_effect=sessions[1:]),
    )

    with pytest.raises(exceptions.RequestException) as raised:
        client.request(
            sdk_request("https://proxy-user:proxy-password@example.com/resource")
        )

    assert sessions[0].request.call_count == 1
    assert sessions[1].request.call_count == 1
    sessions[0].close.assert_called_once_with()
    sessions[1].close.assert_called_once_with()
    assert "proxy-password" not in str(raised.value)
    assert "cHJveHk6c2VjcmV0" not in str(raised.value)


def test_negative_header_parsing_retry_configuration_is_rejected(monkeypatch):
    client = make_client()
    client.session = MagicMock()
    monkeypatch.setenv("OCI_HEADER_PARSING_ERROR_MAX_RETRIES", "-1")

    with pytest.raises(ValueError, match="positive integer"):
        client.request(sdk_request())

    client.session.request.assert_not_called()


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="Linux fd view required")
def test_mocked_transport_reuses_one_session_and_fd_count_plateaus():
    client = make_client()
    session = client.session
    adapter = session.adapters["https://"]
    pool_manager = adapter.poolmanager
    session.request = MagicMock(return_value=successful_response())
    before_fds = len(os.listdir("/proc/self/fd"))

    for _ in range(250):
        assert client.request(sdk_request()).status == 200

    after_fds = len(os.listdir("/proc/self/fd"))
    assert client.session is session
    assert client.session.adapters["https://"].poolmanager is pool_manager
    assert session.request.call_count == 250
    assert after_fds <= before_fds + 1
