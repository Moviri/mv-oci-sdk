import ast
import inspect
import logging
import os
import subprocess
import sys
import time
from unittest.mock import MagicMock, Mock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import oci
from oci import constants, fips
from oci._log_redaction import (
    REDACTED_VALUE,
    redact_sensitive_data_for_logs,
    redact_sensitive_string_for_logs,
)
from oci._vendor import requests
from oci.base_client import BaseClient
from oci.circuit_breaker import CircuitBreakerStrategy, NoCircuitBreakerStrategy
from circuitbreaker import CircuitBreakerMonitor
from oci.auth.signers import OauthExchangeTokenSigner, TokenExchangeSigner
from oci.exceptions import ServiceError, TransientServiceError
from oci.request import Request
from oci.response import Response
from oci.signer import Signer


def valid_config(key_file):
    return {
        "tenancy": "ocid1.tenancy.oc1..aaaa",
        "user": "ocid1.user.oc1..aaaa",
        "fingerprint": ":".join(["aa"] * 16),
        "key_file": str(key_file),
        "region": "us-phoenix-1",
    }


def successful_http_response():
    response = Mock()
    response.status_code = 200
    response.headers = {}
    response.content = b""
    response.elapsed = 0
    return response


def sdk_request():
    return Request(
        "GET",
        "https://example.com/resource",
        header_params={constants.HEADER_REQUEST_ID: "request-id"},
    )


def encoded_security_token(*, lifetime=3600):
    issued_at = int(time.time())
    return jwt.encode(
        {"iat": issued_at, "exp": issued_at + lifetime},
        "test-signing-key-with-at-least-32-bytes",
        algorithm="HS256",
    )


def token_exchange_response(token=None):
    response = MagicMock()
    response.status_code = 200
    response.url = "https://identity.example.com/oauth2/v1/token"
    response.json.return_value = {"token": token or encoded_security_token()}
    return response


def make_token_exchange_signer(session, domain_url="https://identity.example.com"):
    with patch(
        "oci.auth.signers.token_exchange_signer.requests.Session",
        return_value=session,
    ):
        return TokenExchangeSigner(
            "subject-jwt-sentinel",
            domain_url,
            "client-id-sentinel",
            "client-secret-sentinel",
            log_requests=True,
        )


@pytest.mark.parametrize(
    "value",
    [
        "https://proxy-user:proxy-password@proxy.example:8443/path",
        "https://example.com/path?token=query-secret",
        "Authorization: Bearer bearer-secret",
        "{'password': 'json-secret', 'private_key': 'key-secret'}",
    ],
)
def test_sensitive_string_redaction(value):
    redacted = redact_sensitive_string_for_logs(value)

    for secret in (
        "proxy-user",
        "proxy-password",
        "query-secret",
        "bearer-secret",
        "json-secret",
        "key-secret",
    ):
        assert secret not in redacted
    assert REDACTED_VALUE in redacted


def test_nested_service_error_data_redaction():
    value = {
        "message": "safe",
        "accessToken": "token-secret",
        "nested": {"cookie": "cookie-secret"},
    }

    assert redact_sensitive_data_for_logs(value) == {
        "message": "safe",
        "accessToken": REDACTED_VALUE,
        "nested": {"cookie": REDACTED_VALUE},
    }


@pytest.mark.parametrize("error_class", [ServiceError, TransientServiceError])
def test_dynatrace_exception_overlay_omits_timestamp(error_class):
    error = error_class(
        500,
        "InternalError",
        {},
        "failure",
        target_service="compute",
        timestamp=None,
    )

    assert error.timestamp is None
    assert "timestamp" not in str(error)


def test_session_reset_reason_and_cleanup_errors_are_redacted(caplog):
    client = BaseClient(
        "test",
        valid_config("/tmp/mv-oci-sdk-test-key.pem"),
        Mock(),
        {},
        service_endpoint="https://example.com",
    )
    client.logger.disabled = False
    client.logger.propagate = True
    client.session.close = Mock(
        side_effect=RuntimeError("https://user:close-secret@proxy.example")
    )

    with caplog.at_level(logging.WARNING):
        client._reset_session(
            reason="https://user:reason-secret@proxy.example",
        )

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "reason-secret" not in messages
    assert "close-secret" not in messages
    assert REDACTED_VALUE in messages


def test_api_key_configuration_and_request_signing(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    key_file = tmp_path / "oci_api_key.pem"
    key_file.write_bytes(private_key_pem)
    config = valid_config(key_file)

    oci.config.validate_config(config)
    signer = Signer(
        config["tenancy"],
        config["user"],
        config["fingerprint"],
        None,
        private_key_content=private_key_pem,
    )
    request = requests.Request("GET", "https://iaas.example.com/resource").prepare()

    signed_request = signer(request)

    assert signed_request.headers["authorization"].startswith("Signature ")
    assert signed_request.headers["date"]
    assert signed_request.headers["host"] == "iaas.example.com"


def test_openssl_3_fips_guard_does_not_load_legacy_libcrypto(monkeypatch):
    legacy_loader = Mock()
    monkeypatch.setattr(fips, "get_openssl_version", Mock(return_value="3.0.0"))
    monkeypatch.setattr(fips, "override_libcrypto", legacy_loader)

    fips.enable_fips_mode("/tmp/libcrypto.so")

    legacy_loader.assert_not_called()


def test_environment_disabled_circuit_breaker_request_completes():
    code = """
from unittest.mock import Mock
from oci import circuit_breaker, constants
from oci.base_client import BaseClient
from oci.request import Request

assert isinstance(
    circuit_breaker.GLOBAL_CIRCUIT_BREAKER_STRATEGY,
    circuit_breaker.NoCircuitBreakerStrategy,
)
client = BaseClient(
    "test",
    {
        "tenancy": "ocid1.tenancy.oc1..aaaa",
        "user": "ocid1.user.oc1..aaaa",
        "fingerprint": ":".join(["aa"] * 16),
        "key_file": "/tmp/mv-oci-sdk-test-key.pem",
        "region": "us-phoenix-1",
    },
    Mock(),
    {},
    service_endpoint="https://example.com",
    circuit_breaker_strategy=circuit_breaker.GLOBAL_CIRCUIT_BREAKER_STRATEGY,
)
response = Mock(status_code=200, headers={}, content=b"", elapsed=0)
client.session.request = Mock(return_value=response)
result = client.request(
    Request(
        "GET",
        "https://example.com/resource",
        header_params={constants.HEADER_REQUEST_ID: "request-id"},
    )
)
assert result.status == 200
"""
    environment = os.environ.copy()
    environment["OCI_SDK_DEFAULT_CIRCUITBREAKER_ENABLED"] = "false"

    subprocess.run(
        [sys.executable, "-c", code],
        env=environment,
        check=True,
    )


def test_explicit_no_circuit_breaker_request_completes():
    client = BaseClient(
        "test",
        valid_config("/tmp/mv-oci-sdk-test-key.pem"),
        Mock(),
        {},
        service_endpoint="https://example.com",
        circuit_breaker_strategy=NoCircuitBreakerStrategy(),
    )
    client.session.request = Mock(return_value=successful_http_response())

    assert client.request(sdk_request()).status == 200


def test_circuit_breaker_overlay_uses_the_configured_strategy():
    strategy = CircuitBreakerStrategy(name="mv-oci-sdk-test")
    client = BaseClient(
        "test",
        valid_config("/tmp/mv-oci-sdk-test-key.pem"),
        Mock(),
        {},
        service_endpoint="https://example.com",
        circuit_breaker_strategy=strategy,
    )

    assert client.circuit_breaker_strategy is strategy
    assert not hasattr(client, "circuit_breaker_name")

    client.session.request = Mock(return_value=successful_http_response())
    monitored_circuit_breaker = Mock(state="closed")
    with patch.object(
        CircuitBreakerMonitor,
        "get",
        return_value=monitored_circuit_breaker,
    ) as monitor_get:
        assert client.request(sdk_request()).status == 200

    monitor_get.assert_called_once_with(strategy.name)


def test_token_exchange_signer_is_refreshable_after_one_401():
    signer = object.__new__(TokenExchangeSigner)
    signer.refresh_security_token = Mock()
    client = BaseClient(
        "test",
        valid_config("/tmp/mv-oci-sdk-test-key.pem"),
        signer,
        {},
        service_endpoint="https://example.com",
    )
    success = Response(200, {}, "complete", None)
    client.request = Mock(
        side_effect=[
            ServiceError(401, "NotAuthenticated", {}, "expired token"),
            success,
        ]
    )

    assert client.is_instance_principal_or_resource_principal_signer()
    assert client.call_api("/", "GET") is success
    assert client.request.call_count == 2
    signer.refresh_security_token.assert_called_once_with()


def test_token_exchange_signer_propagates_second_401():
    signer = object.__new__(TokenExchangeSigner)
    signer.refresh_security_token = Mock()
    client = BaseClient(
        "test",
        valid_config("/tmp/mv-oci-sdk-test-key.pem"),
        signer,
        {},
        service_endpoint="https://example.com",
    )
    client.request = Mock(
        side_effect=[
            ServiceError(401, "NotAuthenticated", {}, "expired token"),
            ServiceError(401, "NotAuthenticated", {}, "still unauthorized"),
        ]
    )

    with pytest.raises(ServiceError) as raised:
        client.call_api("/", "GET")

    assert raised.value.message == "still unauthorized"
    assert client.request.call_count == 2
    signer.refresh_security_token.assert_called_once_with()


@pytest.mark.parametrize(
    "domain_url",
    [
        "http://identity.example.com",
        "ftp://identity.example.com",
        "https:/identity.example.com",
        "https://identity.example.com?token=query-secret",
        (
            "https://identity.example.com/oauth2/v1/token"
            "/oauth2/v1/token"
        ),
    ],
)
def test_token_exchange_signer_rejects_insecure_or_malformed_urls(domain_url):
    with patch(
        "oci.auth.signers.token_exchange_signer.requests.Session"
    ) as session_factory:
        with pytest.raises(ValueError, match="oci_domain_url|HTTPS"):
            TokenExchangeSigner(
                "subject-jwt-sentinel",
                domain_url,
                "client-id-sentinel",
                "client-secret-sentinel",
            )

    session_factory.assert_not_called()


def test_token_exchange_signer_uses_https_once_and_finite_timeout():
    session = MagicMock()
    session.post.return_value = token_exchange_response()

    signer = make_token_exchange_signer(
        session,
        "https://identity.example.com/oauth2/v1/token/",
    )

    assert signer.get_security_token()
    request_url = session.post.call_args.args[0]
    assert request_url == "https://identity.example.com/oauth2/v1/token"
    assert request_url.count("/oauth2/v1/token") == 1
    assert session.post.call_args.kwargs["timeout"] == (10, 60)


def test_token_exchange_signer_preserves_domain_id_compatibility():
    session = MagicMock()
    session.post.return_value = token_exchange_response()

    make_token_exchange_signer(session, "domain-id")

    assert (
        session.post.call_args.args[0]
        == "https://domain-id.identity.oraclecloud.com/oauth2/v1/token"
    )


@pytest.mark.parametrize("failure_mode", ["missing_token", "malformed", "http_error"])
def test_token_exchange_failures_do_not_log_credentials_or_tokens(
    caplog,
    failure_mode,
):
    sentinels = (
        "subject-jwt-sentinel",
        "client-secret-sentinel",
        "basic-authorization-sentinel",
        "access-token-sentinel",
        "refresh-token-sentinel",
        "exchanged-token-sentinel",
    )
    session = MagicMock()
    response = token_exchange_response()
    if failure_mode == "missing_token":
        response.json.return_value = {
            "error": "exchanged-token-sentinel",
            "refresh_token": "refresh-token-sentinel",
        }
    elif failure_mode == "malformed":
        response.json.side_effect = ValueError("access-token-sentinel")
    else:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "basic-authorization-sentinel"
        )
    session.post.return_value = response

    with caplog.at_level(logging.DEBUG):
        with pytest.raises((RuntimeError, ValueError, requests.exceptions.HTTPError)):
            make_token_exchange_signer(session)

    messages = " ".join(record.getMessage() for record in caplog.records)
    for sentinel in sentinels:
        assert sentinel not in messages


def test_token_exchange_signer_proactive_half_life_refresh():
    session = MagicMock()
    session.post.return_value = token_exchange_response()
    signer = make_token_exchange_signer(session)
    signer.security_token_container.valid_with_half_expiration_time = Mock(
        return_value=False
    )
    signer._refresh_security_token_inner = Mock()

    assert signer.get_security_token() == signer.security_token_container.security_token
    signer._refresh_security_token_inner.assert_called_once_with()


def make_oauth_exchange_signer():
    signer = object.__new__(OauthExchangeTokenSigner)
    signer._setup_logging(True)
    signer.token_signer = Mock()
    signer.cert_bundle_verify = True
    return signer


def oauth_response(*, status_code, ok, url, reason, request_id="request-id"):
    response = MagicMock()
    response.status_code = status_code
    response.ok = ok
    response.url = url
    response.reason = reason
    response.headers = {"opc-request-id": request_id}
    return response


def test_oauth_exchange_endpoint_logging_omits_user_controlled_url(caplog, capsys):
    signer = make_oauth_exchange_signer()
    endpoint = (
        "https://endpoint-user-sentinel:endpoint-password-sentinel@"
        "identity.example.com/oauth?token=endpoint-query-sentinel"
    )

    with caplog.at_level(logging.DEBUG):
        signer._set_oauth_token_endpoint(endpoint)

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert signer.oauth_token_endpoint == endpoint
    assert "OAuth endpoint configured" in messages
    for sentinel in (
        endpoint,
        "endpoint-user-sentinel",
        "endpoint-password-sentinel",
        "endpoint-query-sentinel",
    ):
        assert sentinel not in messages
    assert capsys.readouterr().out == ""


def test_oauth_exchange_exception_logging_omits_exception_text(caplog, capsys):
    signer = make_oauth_exchange_signer()
    signer.oauth_token_endpoint = (
        "https://exception-user-sentinel:exception-password-sentinel@"
        "identity.example.com/oauth"
    )
    exception_message = "client-secret-sentinel response-token-sentinel"

    with (
        patch.object(signer, "_ensure_token_signer_current"),
        patch.object(
            signer,
            "_post_oauth_request",
            side_effect=RuntimeError(exception_message),
        ),
        caplog.at_level(logging.DEBUG),
        pytest.raises(RuntimeError) as raised,
    ):
        signer._make_oauth_request({}, {})

    assert str(raised.value) == exception_message
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "RuntimeError" in messages
    for sentinel in (
        signer.oauth_token_endpoint,
        "exception-user-sentinel",
        "exception-password-sentinel",
        "client-secret-sentinel",
        "response-token-sentinel",
    ):
        assert sentinel not in messages
    assert capsys.readouterr().out == ""


def test_oauth_exchange_response_logging_omits_url_reason_and_body(caplog, capsys):
    signer = make_oauth_exchange_signer()
    response = oauth_response(
        status_code=400,
        ok=False,
        url=(
            "https://response-user-sentinel:response-password-sentinel@"
            "identity.example.com/oauth?token=response-query-sentinel"
        ),
        reason="response-reason-secret-sentinel",
        request_id="safe-request-id",
    )

    with caplog.at_level(logging.DEBUG):
        signer._log_oauth_response(response, "initial")

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "status_code" in messages
    assert "safe-request-id" in messages
    for sentinel in (
        response.url,
        "response-user-sentinel",
        "response-password-sentinel",
        "response-query-sentinel",
        "response-reason-secret-sentinel",
    ):
        assert sentinel not in messages

    decoded_response = '{"client_secret": "decoded-body-secret-sentinel"}'
    with pytest.raises(RuntimeError) as raised:
        signer._get_security_token(decoded_response)
    assert "decoded-body-secret-sentinel" not in str(raised.value)
    assert capsys.readouterr().out == ""


def test_oauth_exchange_401_refreshes_and_retries_once_without_secret_logs(
    caplog,
    capsys,
):
    signer = make_oauth_exchange_signer()
    signer.oauth_token_endpoint = (
        "https://retry-user-sentinel:retry-password-sentinel@"
        "identity.example.com/oauth"
    )
    unauthorized = oauth_response(
        status_code=401,
        ok=False,
        url=signer.oauth_token_endpoint,
        reason="retry-reason-secret-sentinel",
    )
    success = oauth_response(
        status_code=200,
        ok=True,
        url=signer.oauth_token_endpoint,
        reason="success-reason-secret-sentinel",
    )

    with (
        patch.object(signer, "_ensure_token_signer_current"),
        patch.object(signer, "_force_refresh_token_signer", return_value=True),
        patch.object(
            signer,
            "_post_oauth_request",
            side_effect=[unauthorized, success],
        ) as post_oauth_request,
        caplog.at_level(logging.DEBUG),
    ):
        result = signer._make_oauth_request({}, {})

    assert result is success
    assert post_oauth_request.call_count == 2
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "attempt': 'initial" in messages
    assert "attempt': 'retry" in messages
    for sentinel in (
        signer.oauth_token_endpoint,
        "retry-user-sentinel",
        "retry-password-sentinel",
        "retry-reason-secret-sentinel",
        "success-reason-secret-sentinel",
    ):
        assert sentinel not in messages
    assert capsys.readouterr().out == ""


def test_oauth_exchange_logging_sinks_reject_sensitive_values_and_stdout():
    source = inspect.getsource(OauthExchangeTokenSigner)
    tree = ast.parse(source)
    prohibited_log_inputs = (
        "oauth_token_endpoint",
        "target_compartment",
        "self.scope",
        "_session_key_fingerprint",
        "_security_token_expiration",
        "_security_token_age_seconds",
        "_is_security_token_valid",
        "response.url",
        "response.reason",
        "str(error)",
        "str(e)",
        "decoded_response",
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            pytest.fail("OAuth exchange diagnostics must not write directly to stdout")
        if not (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "logger"
        ):
            continue

        log_call = ast.unparse(node)
        for prohibited in prohibited_log_inputs:
            assert prohibited not in log_call
