import http.client
import io
import logging
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, Mock, patch

import pytest
import urllib3
from urllib3.exceptions import HeaderParsingError, ProtocolError

from oci import constants, exceptions, retry
from oci._vendor import requests
from oci.base_client import (
    BaseClient,
    OPC_INCOMING_REQUEST_ID_ENV_VAR_NAME,
    OCIConnection,
    OCIConnectionPool,
    OCIHTTPAdapter,
    OCIPoolManager,
    OCIProxyManager,
)
from oci.monitoring import MonitoringClient
from oci.object_storage import ObjectStorageClient
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


class NonClosingSocketFile:
    def __init__(self, buffer):
        self.buffer = buffer

    def __getattr__(self, name):
        return getattr(self.buffer, name)

    def close(self):
        pass


class FakeSocket:
    def __init__(self, response_bytes):
        self.response_buffer = io.BytesIO(response_bytes)
        self.sent = bytearray()
        self.closed = False
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.extend(data)

    def makefile(self, *args, **kwargs):
        return NonClosingSocketFile(self.response_buffer)

    def shutdown(self, *args):
        pass

    def close(self):
        self.closed = True


def fake_connection(response_bytes):
    connection = OCIConnection("example.com")
    socket = FakeSocket(response_bytes)
    connection.sock = socket
    return connection, socket


def split_wire_request(socket):
    headers, separator, body = bytes(socket.sent).partition(b"\r\n\r\n")
    assert separator == b"\r\n\r\n"
    return headers + separator, body


def valid_config():
    return {
        "tenancy": "ocid1.tenancy.oc1..aaaa",
        "user": "ocid1.user.oc1..aaaa",
        "fingerprint": ":".join(["aa"] * 16),
        "key_file": "/tmp/mv-oci-sdk-test-key.pem",
        "region": "us-phoenix-1",
    }


def make_client(log_requests=False):
    config = valid_config()
    config["log_requests"] = log_requests
    return BaseClient(
        "test",
        config,
        Mock(),
        {},
        service_endpoint="https://example.com",
    )


def successful_response(status_code=200, headers=None, content=b""):
    response = Mock()
    response.status_code = status_code
    response.headers = headers or {}
    response.content = content
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


def test_real_malformed_response_is_sanitized_and_discards_connection(
    caplog,
    capsys,
):
    sentinel = "response-cookie-secret-sentinel"
    connection, socket = fake_connection(
        (
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Malformed Header Line\r\n"
            f"Set-Cookie: session={sentinel}\r\n"
            "\r\n"
        ).encode()
    )

    with caplog.at_level(logging.WARNING, logger="urllib3.connection"):
        connection.request("GET", "/resource", headers={})
        with pytest.raises(HeaderParsingError) as raised:
            connection.getresponse()

    captured_output = capsys.readouterr()
    diagnostics = " ".join(
        (
            str(raised.value),
            captured_output.out,
            captured_output.err,
            *(record.getMessage() for record in caplog.records),
        )
    )
    assert sentinel not in diagnostics
    assert "Failed to parse headers" not in diagnostics
    assert connection.sock is None
    assert socket.closed


def test_real_valid_response_preserves_urllib3_response_options():
    connection, _ = fake_connection(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: valid\r\n\r\nok"
    )

    connection.request(
        "GET",
        "/resource",
        headers={},
        preload_content=False,
        decode_content=False,
        enforce_content_length=True,
    )
    response = connection.getresponse()

    assert response.status == 200
    assert response.reason == "OK"
    assert response.headers["X-Test"] == "valid"
    assert response._request_url == "/resource"
    assert response.decode_content is False
    assert response.enforce_content_length is True
    assert response._original_response is not None
    assert response.read() == b"ok"


def test_base_client_resets_once_for_real_malformed_response(
    monkeypatch,
    caplog,
    capsys,
):
    connection, socket = fake_connection(
        (
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Malformed Header Line\r\n"
            "Set-Cookie: session=response-cookie-secret-sentinel\r\n"
            "\r\n"
        ).encode()
    )

    class ConnectionSession:
        def __init__(self):
            self.request_count = 0
            self.close_count = 0

        def request(self, method, url, **kwargs):
            self.request_count += 1
            connection.request(method, "/resource", headers=kwargs["headers"])
            return connection.getresponse()

        def close(self):
            self.close_count += 1

    client = make_client()
    old_session = ConnectionSession()
    replacement_session = MagicMock()
    client.session = old_session
    monkeypatch.setattr(
        "oci.base_client.copy.copy",
        Mock(return_value=replacement_session),
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(exceptions.RequestException) as raised:
            client.request(sdk_request())

    captured_output = capsys.readouterr()
    diagnostics = " ".join(
        (
            str(raised.value),
            captured_output.out,
            captured_output.err,
            *(record.getMessage() for record in caplog.records),
        )
    )
    assert "response-cookie-secret-sentinel" not in diagnostics
    assert old_session.request_count == 1
    assert old_session.close_count == 1
    replacement_session.request.assert_not_called()
    assert client.session is replacement_session
    assert connection.sock is None
    assert socket.closed


def test_no_expect_header_uses_normal_urllib3_body_path(monkeypatch):
    connection, socket = fake_connection(b"")
    wait_for_read = Mock(return_value=True)
    monkeypatch.setattr(urllib3.util, "wait_for_read", wait_for_read)

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={"Content-Length": "7"},
    )

    _, body = split_wire_request(socket)
    assert body == b"payload"
    wait_for_read.assert_not_called()


def test_expect_timeout_sends_body_once(monkeypatch):
    connection, socket = fake_connection(b"")
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=False))

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={"Expect": "100-continue", "Content-Length": "7"},
    )

    headers, body = split_wire_request(socket)
    assert b"Expect: 100-continue\r\n" in headers
    assert body == b"payload"


def test_expect_100_continue_sends_headers_before_body_once(monkeypatch):
    connection, socket = fake_connection(
        (
            b"HTTP/1.1 100 Continue\r\nX-Interim: accepted\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
    )
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={"Expect": "100-continue", "Content-Length": "7"},
    )
    response = connection.getresponse()

    _, body = split_wire_request(socket)
    assert body == b"payload"
    assert response.status == 200


@pytest.mark.parametrize("status", (401, 412, 413))
def test_expect_immediate_final_response_preserves_status_and_sends_no_body(
    monkeypatch,
    status,
):
    connection, socket = fake_connection(
        (
            f"HTTP/1.1 {status} Rejected\r\n"
            "Content-Length: 0\r\n"
            "X-Test: early-final\r\n"
            "\r\n"
        ).encode()
    )
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={"Expect": "100-continue", "Content-Length": "7"},
        preload_content=False,
        decode_content=False,
        enforce_content_length=True,
    )
    response = connection.getresponse()

    _, body = split_wire_request(socket)
    assert body == b""
    assert response.status == status
    assert response.headers["X-Test"] == "early-final"
    assert response._request_url == "/resource"
    assert response.decode_content is False
    assert response.enforce_content_length is True


def test_expect_immediate_final_does_not_advance_chunked_generator(monkeypatch):
    connection, socket = fake_connection(
        b"HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n"
    )
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))
    iterations = []

    def body():
        iterations.append("started")
        yield b"payload"

    connection.request(
        "PUT",
        "/resource",
        body=body(),
        headers={"Expect": "100-continue"},
        chunked=True,
    )
    response = connection.getresponse()

    headers, wire_body = split_wire_request(socket)
    assert response.status == 413
    assert iterations == []
    assert b"Transfer-Encoding: chunked\r\n" in headers
    assert wire_body == b""


def test_expect_state_is_reset_on_reused_connection(monkeypatch):
    connection, socket = fake_connection(
        b"HTTP/1.1 412 Rejected\r\nContent-Length: 0\r\n\r\n"
    )
    wait_for_read = Mock(return_value=True)
    monkeypatch.setattr(urllib3.util, "wait_for_read", wait_for_read)

    connection.request(
        "PUT",
        "/first",
        body=b"first",
        headers={"Expect": "100-continue", "Content-Length": "5"},
    )
    assert connection.getresponse().status == 412
    connection.request(
        "PUT",
        "/second",
        body=b"second",
        headers={"Content-Length": "6"},
    )

    assert bytes(socket.sent).endswith(b"\r\n\r\nsecond")
    wait_for_read.assert_called_once()


@pytest.mark.parametrize(
    "wire_response",
    (
        b"",
        b"HTTP/1.1 100 Continue\r\nX-Incomplete: true\r\n",
        b"HTTP/1.1 100 Continue\r\nMalformed Header\r\n\r\n",
        b"not-http\r\n\r\n",
    ),
)
def test_expect_invalid_interim_response_fails_without_consuming_body(
    monkeypatch,
    wire_response,
):
    connection, socket = fake_connection(wire_response)
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))
    iterations = []

    def body():
        iterations.append("started")
        yield b"payload"

    with pytest.raises(ProtocolError):
        connection.request(
            "PUT",
            "/resource",
            body=body(),
            headers={"Expect": "100-continue"},
            chunked=True,
        )

    assert iterations == []
    assert connection.sock is None
    assert socket.closed
    _, wire_body = split_wire_request(socket)
    assert wire_body == b""


def test_expect_other_informational_response_is_handled_before_continue(
    monkeypatch,
):
    connection, socket = fake_connection(
        (
            b"HTTP/1.1 103 Early Hints\r\nLink: </resource>\r\n\r\n"
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
    )
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={"Expect": "100-continue", "Content-Length": "7"},
    )

    _, body = split_wire_request(socket)
    assert body == b"payload"
    assert connection.getresponse().status == 200


@pytest.mark.parametrize(
    ("header", "value"),
    (
        ("Expect", "100-continue"),
        ("EXPECT", "100-CONTINUE"),
        ("eXpEcT", "  100-Continue  "),
    ),
)
def test_expect_header_matching_is_case_and_whitespace_insensitive(
    monkeypatch,
    header,
    value,
):
    connection, socket = fake_connection(
        b"HTTP/1.1 413 Rejected\r\nContent-Length: 0\r\n\r\n"
    )
    wait_for_read = Mock(return_value=True)
    monkeypatch.setattr(urllib3.util, "wait_for_read", wait_for_read)

    connection.request(
        "PUT",
        "/resource",
        body=b"payload",
        headers={header: value, "Content-Length": "7"},
    )

    assert connection.getresponse().status == 413
    _, body = split_wire_request(socket)
    assert body == b""
    wait_for_read.assert_called_once()


def test_expect_early_final_uses_malformed_header_protection(
    monkeypatch,
    caplog,
):
    sentinel = "early-response-cookie-secret-sentinel"
    connection, socket = fake_connection(
        (
            "HTTP/1.1 413 Rejected\r\n"
            "Content-Length: 0\r\n"
            "Malformed Header Line\r\n"
            f"Set-Cookie: session={sentinel}\r\n"
            "\r\n"
        ).encode()
    )
    monkeypatch.setattr(urllib3.util, "wait_for_read", Mock(return_value=True))

    with caplog.at_level(logging.WARNING, logger="urllib3.connection"):
        connection.request(
            "PUT",
            "/resource",
            body=b"payload",
            headers={"Expect": "100-continue", "Content-Length": "7"},
        )
        with pytest.raises(HeaderParsingError) as raised:
            connection.getresponse()

    diagnostics = " ".join(
        (str(raised.value), *(record.getMessage() for record in caplog.records))
    )
    assert sentinel not in diagnostics
    assert "Failed to parse headers" not in diagnostics
    assert connection.sock is None
    assert socket.closed
    _, body = split_wire_request(socket)
    assert body == b""


@pytest.mark.parametrize("operation", ("put_object", "upload_part"))
def test_object_storage_upload_operations_retain_expect_default(operation):
    client = ObjectStorageClient(
        valid_config(),
        signer=Mock(),
        service_endpoint="https://objectstorage.example.com",
    )
    client.base_client.call_api = Mock(return_value="response")
    none_retry = retry.NoneRetryStrategy()

    if operation == "put_object":
        result = client.put_object(
            "namespace",
            "bucket",
            "object",
            b"payload",
            retry_strategy=none_retry,
        )
    else:
        result = client.upload_part(
            "namespace",
            "bucket",
            "object",
            "upload-id",
            1,
            b"payload",
            retry_strategy=none_retry,
        )

    assert result == "response"
    assert client.base_client.call_api.call_args.kwargs["header_params"]["expect"] == "100-continue"


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


def test_header_parsing_error_is_single_attempt_for_rewindable_put(monkeypatch):
    client = make_client()
    old_session = MagicMock()
    new_session = MagicMock()
    body = io.BytesIO(b"payload")
    observed_bodies = []

    def fail_after_consuming_body(*args, **kwargs):
        observed_bodies.append(kwargs["data"].read())
        raise HeaderParsingError(
            ["Authorization: Bearer first-secret"],
            b"",
        )

    old_session.request.side_effect = fail_after_consuming_body
    client.session = old_session
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))

    request = Request(
        "PUT",
        "https://example.com/resource",
        header_params={constants.HEADER_REQUEST_ID: "request-id"},
        body=body,
    )
    with pytest.raises(exceptions.RequestException):
        client.request(request)

    assert observed_bodies == [b"payload"]
    assert old_session.request.call_count == 1
    new_session.request.assert_not_called()
    assert client.session is new_session
    old_session.close.assert_called_once_with()


@pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "DELETE"))
def test_header_parsing_error_is_single_shot_and_redacted_for_unsafe_methods(
    monkeypatch,
    method,
):
    client = make_client()
    old_session = MagicMock()
    new_session = MagicMock()
    old_session.request.side_effect = HeaderParsingError(
        ["Proxy-Authorization: Basic cHJveHk6c2VjcmV0"],
        b"",
    )
    client.session = old_session
    monkeypatch.setenv("OCI_HEADER_PARSING_ERROR_MAX_RETRIES", "100")
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))

    with pytest.raises(exceptions.RequestException) as raised:
        client.request(
            Request(
                method,
                "https://proxy-user:proxy-password@example.com/resource",
                header_params={constants.HEADER_REQUEST_ID: "request-id"},
                body=b"payload",
            )
        )

    assert old_session.request.call_count == 1
    old_session.close.assert_called_once_with()
    new_session.request.assert_not_called()
    assert "proxy-password" not in str(raised.value)
    assert "cHJveHk6c2VjcmV0" not in str(raised.value)


def test_header_parsing_error_does_not_replay_generator_body(monkeypatch):
    client = make_client()
    old_session = MagicMock()
    new_session = MagicMock()
    iterations = []

    def body():
        iterations.append("started")
        yield b"first"
        yield b"second"

    request_body = body()

    def fail_after_consuming_body(*args, **kwargs):
        assert list(kwargs["data"]) == [b"first", b"second"]
        raise HeaderParsingError([], b"")

    old_session.request.side_effect = fail_after_consuming_body
    client.session = old_session
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))

    with pytest.raises(exceptions.RequestException):
        client.request(
            Request(
                "POST",
                "https://example.com/resource",
                header_params={constants.HEADER_REQUEST_ID: "request-id"},
                body=request_body,
            )
        )

    assert iterations == ["started"]
    assert old_session.request.call_count == 1
    new_session.request.assert_not_called()


def test_monitoring_none_retry_strategy_is_single_transport_attempt(monkeypatch):
    client = MonitoringClient(
        valid_config(),
        signer=Mock(),
        service_endpoint="https://telemetry-ingestion.example.com",
    )
    old_session = MagicMock()
    new_session = MagicMock()
    old_session.request.side_effect = HeaderParsingError([], b"")
    client.base_client.session = old_session
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))

    with pytest.raises(exceptions.RequestException):
        client.post_metric_data(
            {"metricData": []},
            retry_strategy=retry.NoneRetryStrategy(),
        )

    assert old_session.request.call_count == 1
    new_session.request.assert_not_called()


def test_monitoring_explicit_retry_owns_the_second_transport_attempt(monkeypatch):
    client = MonitoringClient(
        valid_config(),
        signer=Mock(),
        service_endpoint="https://telemetry-ingestion.example.com",
    )
    old_session = MagicMock()
    new_session = MagicMock()
    old_session.request.side_effect = HeaderParsingError([], b"")
    new_session.request.return_value = successful_response(
        200,
        {"content-type": "application/json"},
        b"{}",
    )
    client.base_client.session = old_session
    monkeypatch.setattr("oci.base_client.copy.copy", Mock(return_value=new_session))
    strategy = retry.RetryStrategyBuilder(
        max_attempts=2,
        total_elapsed_time_check=False,
        retry_base_sleep_time_seconds=0,
    ).get_retry_strategy()
    strategy.do_sleep = Mock()

    response = client.post_metric_data(
        {"metricData": []},
        retry_strategy=strategy,
    )

    assert response.status == 200
    assert old_session.request.call_count == 1
    assert new_session.request.call_count == 1
    old_session.close.assert_called_once_with()
    strategy.do_sleep.assert_called_once()


def test_explicit_outer_retry_retains_existing_rewind_contract():
    class CountingBytesIO(io.BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.seek_count = 0

        def seek(self, *args, **kwargs):
            self.seek_count += 1
            return super().seek(*args, **kwargs)

    class RetryingCall:
        def __init__(self):
            self.observed_bodies = []

        def call_api(self, *, body):
            self.observed_bodies.append(body.read())
            if len(self.observed_bodies) == 1:
                raise exceptions.RequestException("retryable")
            return "success"

    strategy = retry.RetryStrategyBuilder(
        max_attempts=2,
        total_elapsed_time_check=False,
        retry_base_sleep_time_seconds=0,
    ).get_retry_strategy()
    strategy.do_sleep = Mock()
    call = RetryingCall()
    body = CountingBytesIO(b"payload")

    assert strategy.make_retrying_call(call.call_api, body=body) == "success"
    assert call.observed_bodies == [b"payload", b"payload"]
    assert body.seek_count == 1
    strategy.do_sleep.assert_called_once()


@pytest.mark.parametrize(
    ("status_code", "response_headers"),
    (
        (200, {}),
        (204, {}),
        (200, {constants.HEADER_REQUEST_ID: ""}),
        (200, {constants.HEADER_REQUEST_ID: None}),
    ),
)
def test_propagation_tolerates_missing_or_empty_response_request_id(
    monkeypatch,
    status_code,
    response_headers,
):
    client = make_client()
    client.PROPAGATION_ENABLED = True
    client.session = MagicMock(
        request=MagicMock(
            return_value=successful_response(status_code, response_headers)
        )
    )
    monkeypatch.setenv(OPC_INCOMING_REQUEST_ID_ENV_VAR_NAME, "incoming-sentinel")

    response = client.request(
        Request("GET", "https://example.com/resource", header_params={})
    )

    assert response.status == status_code
    assert os.environ[OPC_INCOMING_REQUEST_ID_ENV_VAR_NAME] == "incoming-sentinel"


def test_propagation_records_present_response_request_id(monkeypatch):
    client = make_client()
    client.PROPAGATION_ENABLED = True
    client.session = MagicMock(
        request=MagicMock(
            return_value=successful_response(
                200,
                {constants.HEADER_REQUEST_ID: "response-request-id"},
            )
        )
    )
    monkeypatch.setenv(OPC_INCOMING_REQUEST_ID_ENV_VAR_NAME, "incoming-sentinel")

    response = client.request(
        Request("GET", "https://example.com/resource", header_params={})
    )

    assert response.status == 200
    assert os.environ[OPC_INCOMING_REQUEST_ID_ENV_VAR_NAME] == "response-request-id"


def test_log_requests_does_not_enable_process_global_wire_logging(
    caplog,
    capsys,
):
    original_debuglevel = http.client.HTTPConnection.debuglevel
    http.client.HTTPConnection.debuglevel = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), RequestBodyRecorder)
    server.received_requests = []
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    connection = None
    sentinels = (
        "basic-authorization-sentinel",
        "proxy-authorization-sentinel",
        "client-secret-sentinel",
        "subject-jwt-sentinel",
        "access-token-sentinel",
        "security-token-sentinel",
        "refresh-token-sentinel",
    )
    encoded_form_body = (
        "client_secret=client-secret-sentinel&"
        "subject_token=subject-jwt-sentinel&"
        "access_token=access-token-sentinel&"
        "security_token=security-token-sentinel&"
        "refresh_token=refresh-token-sentinel"
    )

    try:
        with caplog.at_level(logging.DEBUG):
            make_client(log_requests=True)
            assert http.client.HTTPConnection.debuglevel == 0
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                server.server_port,
                timeout=2,
            )
            connection.request(
                "POST",
                "/oauth",
                body=encoded_form_body,
                headers={
                    "Authorization": "Basic basic-authorization-sentinel",
                    "Proxy-Authorization": "Basic proxy-authorization-sentinel",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response = connection.getresponse()
            assert response.read() == b"ok"
            make_client(log_requests=False)
            assert http.client.HTTPConnection.debuglevel == 0
    finally:
        if connection is not None:
            connection.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        http.client.HTTPConnection.debuglevel = original_debuglevel

    assert server.received_requests[0]["body"] == encoded_form_body.encode()
    captured_output = capsys.readouterr()
    diagnostics = " ".join(
        (
            captured_output.out,
            captured_output.err,
            *(record.getMessage() for record in caplog.records),
        )
    )
    for sentinel in (*sentinels, encoded_form_body):
        assert sentinel not in diagnostics



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
