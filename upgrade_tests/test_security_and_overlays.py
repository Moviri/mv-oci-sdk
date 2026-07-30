import logging
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import oci
from oci import fips
from oci._log_redaction import (
    REDACTED_VALUE,
    redact_sensitive_data_for_logs,
    redact_sensitive_string_for_logs,
)
from oci._vendor import requests
from oci.base_client import BaseClient
from oci.circuit_breaker import CircuitBreakerStrategy
from oci.exceptions import ServiceError, TransientServiceError
from oci.signer import Signer


def valid_config(key_file):
    return {
        "tenancy": "ocid1.tenancy.oc1..aaaa",
        "user": "ocid1.user.oc1..aaaa",
        "fingerprint": ":".join(["aa"] * 16),
        "key_file": str(key_file),
        "region": "us-phoenix-1",
    }


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
