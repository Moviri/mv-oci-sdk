# coding: utf-8
# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

import threading
import base64
import logging
import re
from urllib.parse import urlparse, urlunparse


from oci._vendor import requests
from oci._log_redaction import redact_sensitive_string_for_logs
from oci.auth.session_key_supplier import SessionKeySupplier
from oci.auth.security_token_container import SecurityTokenContainer
from oci.auth.signers.security_token_signer import SecurityTokenSigner, SECURITY_TOKEN_FORMAT_STRING
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


TOKEN_EXCHANGE_PATH = "/oauth2/v1/token"
TOKEN_EXCHANGE_TIMEOUT = (10, 60)
OCI_DOMAIN_ID_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def _token_exchange_endpoint(oci_domain_url):
    if not isinstance(oci_domain_url, str) or not oci_domain_url.strip():
        raise ValueError(
            "Missing oci_domain_url. Either provide an HTTPS URL or domain ID."
        )

    value = oci_domain_url.strip()
    if "://" not in value:
        if not OCI_DOMAIN_ID_PATTERN.fullmatch(value):
            raise ValueError(
                "Invalid oci_domain_url. Provide an HTTPS URL or a valid domain ID."
            )
        return f"https://{value}.identity.oraclecloud.com{TOKEN_EXCHANGE_PATH}"

    parsed = urlparse(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("Invalid oci_domain_url. Token exchange requires HTTPS.")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Invalid oci_domain_url. An HTTPS hostname is required.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Invalid oci_domain_url. User information is not allowed.")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("Invalid oci_domain_url. The port is malformed.") from error
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Invalid oci_domain_url. Query strings and fragments are not allowed."
        )

    path = parsed.path.rstrip("/")
    token_path_occurrences = path.count(TOKEN_EXCHANGE_PATH)
    if token_path_occurrences > 1 or (
        token_path_occurrences == 1 and not path.endswith(TOKEN_EXCHANGE_PATH)
    ):
        raise ValueError("Invalid oci_domain_url. The token path is malformed.")
    if not path.endswith(TOKEN_EXCHANGE_PATH):
        path = f"{path}{TOKEN_EXCHANGE_PATH}"

    return urlunparse(("https", parsed.netloc, path, "", "", ""))


class TokenExchangeSigner(SecurityTokenSigner):
    """
    OCI Python SDK signer for OAuth2 Token Exchange (UPST) authentication.
    Automatically refreshes tokens as needed, suitable for use with OCI SDK clients.
    """

    def __init__(self, jwt_or_func, oci_domain_url, client_id, client_secret, region=None, **kwargs):
        # Initialize per-instance logger
        self.logger = logging.getLogger(f"{__name__}.{id(self)}")
        self.logger.addHandler(logging.NullHandler())

        # Enable or disable logging based on argument
        if kwargs.get('log_requests'):
            self.logger.disabled = False
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.disabled = True

        if isinstance(oci_domain_url, str) and "://" not in oci_domain_url:
            self.logger.warning(
                "Passing an OCI domain ID is deprecated; use an HTTPS identity domain URL."
            )

        if callable(jwt_or_func):
            self.jwt_function = jwt_or_func
        else:
            self.jwt_function = lambda: jwt_or_func

        self.client_id = client_id
        self.client_secret = client_secret
        self.oci_domain_url = oci_domain_url
        self.token_exchange_endpoint = _token_exchange_endpoint(oci_domain_url)
        self.region = region

        self._reset_signers_lock = threading.Lock()
        self.requests_session = requests.Session()
        self.session_key_supplier = SessionKeySupplier()

        self.logger.debug(
            "Initializing TokenExchangeSigner for endpoint: %s",
            redact_sensitive_string_for_logs(self.token_exchange_endpoint),
        )

        token = self._get_new_token()
        self.security_token_container = SecurityTokenContainer(self.session_key_supplier, token)

        generic_headers = kwargs.get("generic_headers", ["date", "(request-target)", "host"])
        super().__init__(
            self.security_token_container.security_token,
            self.session_key_supplier.get_key_pair()['private'],
            generic_headers=generic_headers
        )

    def __call__(self, request, enforce_content_headers=True):
        if not self.security_token_container.valid():
            self.logger.debug("Security token invalid or expired. Refreshing token.")
            self._refresh_security_token_inner()
        return super().__call__(request, enforce_content_headers)

    def _get_jwt(self):
        return self.jwt_function()

    def get_security_token(self):
        # Proactively refresh if token is past half its lifetime
        if self.security_token_container.valid_with_half_expiration_time():
            self.logger.debug("Security token still valid (within half-life).")
            return self.security_token_container.security_token
        else:
            self.logger.debug("Security token past half-life. Refreshing token.")
            self._refresh_security_token_inner()
            return self.security_token_container.security_token

    def refresh_security_token(self):
        self._refresh_security_token_inner()
        return self.security_token_container.security_token

    def _refresh_security_token_inner(self):
        with self._reset_signers_lock:
            self.logger.debug("Refreshing session key supplier and security token.")
            self.session_key_supplier.refresh()
            token = self._get_new_token()
            self.logger.debug("New private key PEM generated (not shown for security).")
            self.security_token_container = SecurityTokenContainer(self.session_key_supplier, token)
            self._reset_signers()

    def _reset_signers(self):
        self.api_key = SECURITY_TOKEN_FORMAT_STRING.format(self.security_token_container.security_token)
        self.private_key = self.session_key_supplier.get_key_pair()['private']
        if hasattr(self, '_basic_signer'):
            self._basic_signer.reset_signer(self.api_key, self.private_key)
        if hasattr(self, '_body_signer'):
            self._body_signer.reset_signer(self.api_key, self.private_key)
        self.logger.debug("Signers reset with new API key and private key.")

    def _get_new_token(self):
        """
        Requests a new UPST token from the token exchange endpoint.
        Supports both oci_domain_url (preferred) and oci_domain_id (deprecated).
        """
        try:
            subject_token = self._get_jwt()
            private_key = self.session_key_supplier.private_key
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8").replace("\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
            encoded_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode("utf-8")).decode("utf-8")
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {encoded_auth}"
            }

            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:oci:token-type:oci-upst",
                "subject_token": subject_token,
                "subject_token_type": "jwt",
                "public_key": public_key_pem
            }

            self.logger.debug(
                "Requesting UPST token from: %s",
                redact_sensitive_string_for_logs(self.token_exchange_endpoint),
            )

            response = self.requests_session.post(
                self.token_exchange_endpoint,
                headers=headers,
                data=data,
                timeout=TOKEN_EXCHANGE_TIMEOUT,
            )
            self.logger.debug(
                "Token exchange response status: %s", response.status_code
            )

            response.raise_for_status()
            response_json = response.json()

            if (
                not isinstance(response_json, dict)
                or not isinstance(response_json.get("token"), str)
                or not response_json["token"]
            ):
                self.logger.error(
                    "Token exchange response did not contain a usable token."
                )
                raise RuntimeError("'token' not found in token exchange response")

            self.logger.debug("Successfully obtained new UPST token.")
            return response_json["token"]

        except Exception as e:
            self.logger.error(
                "Failed to get new token (%s).", type(e).__name__
            )
            raise
