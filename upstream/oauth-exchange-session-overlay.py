    def _make_oauth_request(self, headers, payload):
        """Execute the authenticated HTTP request to the OAuth endpoint"""
        # The OAuth exchange is signed by token_signer directly, outside BaseClient's
        # normal retry path. Give refreshable signers a chance to renew first.
        self.logger.debug(
            "%s Ensuring wrapped token signer is current token_signer=%s",
            self.LOG_PREFIX,
            self._token_signer_name(),
        )
        self._ensure_token_signer_current()

        self.logger.debug(
            "%s Requesting OAuth token token_signer=%s",
            self.LOG_PREFIX,
            self._token_signer_name(),
        )
        # Make POST request to OAuth endpoint, authenticated with the original token_signer
        with requests.Session() as session:
            try:
                response = self._post_oauth_request(session, headers, payload)
            except Exception as error:
                self.logger.error(
                    "%s OAuth token request failed before response attempt=initial token_signer=%s error_type=%s",
                    self.LOG_PREFIX,
                    self._token_signer_name(),
                    type(error).__name__,
                )
                raise
            self._log_oauth_response(response, "initial")
            if response.status_code == 401 and self._force_refresh_token_signer():
                # A 401 here is an AuthN failure for the wrapped signer, so retry once
                # after forcing the same kind of token refresh BaseClient performs.
                self.logger.debug(
                    "%s Retrying OAuth token exchange after wrapped signer refresh token_signer=%s",
                    self.LOG_PREFIX,
                    self._token_signer_name(),
                )
                try:
                    response = self._post_oauth_request(session, headers, payload)
                except Exception as error:
                    self.logger.error(
                        "%s OAuth token request failed before response attempt=retry token_signer=%s error_type=%s",
                        self.LOG_PREFIX,
                        self._token_signer_name(),
                        type(error).__name__,
                    )
                    raise
                self._log_oauth_response(response, "retry")

            return response

    def _post_oauth_request(self, session, headers, payload):
        return session.post(self.oauth_token_endpoint,
                            json=payload,  # JSON payload with scope, public_key, target_compartment
                            headers=headers,  # Content-Type: application/json
                            auth=self.token_signer,  # Original signer (e.g., instance principal)
                            verify=self.cert_bundle_verify,  # SSL verification
                            timeout=(10, 60),  # Connection and read timeouts
                            stream=False)  # Buffer response content before session closure
