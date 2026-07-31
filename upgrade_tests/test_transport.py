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
    OCIConnectionPool,
    OCIHTTPAdapter,
    OCIPoolManager,
    OCIProxyManager,
)
from oci.monitoring import MonitoringClient
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
