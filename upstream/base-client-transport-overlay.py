def _to_bytes(input_buffer):
    bytes_buffer = []
    for chunk in input_buffer:
        if isinstance(chunk, six.text_type):
            bytes_buffer.append(chunk.encode("utf-8"))
        else:
            bytes_buffer.append(chunk)
    return b"\r\n".join(bytes_buffer)


def _sanitized_header_parsing_error():
    return HeaderParsingError([], b"")


def _validate_response_headers(message):
    try:
        assert_header_parsing(message)
    except (HeaderParsingError, TypeError):
        raise _sanitized_header_parsing_error() from None


def _read_interim_headers(fp):
    header_lines = []
    for _ in range(_MAXHEADERS + 1):
        line = fp.readline(_MAXLINE + 1)
        if not line:
            raise _OCIExpectResponseError(
                "Incomplete response during Expect handling"
            )
        if len(line) > _MAXLINE:
            raise _OCIExpectResponseError(
                "Invalid response during Expect handling"
            )
        if line in (b"\r\n", b"\n"):
            break
        header_lines.append(line)
    else:
        raise _OCIExpectResponseError(
            "Invalid response during Expect handling"
        )

    try:
        message = parse_headers(
            io.BytesIO(b"".join(header_lines) + b"\r\n")
        )
        _validate_response_headers(message)
    except HeaderParsingError:
        raise _OCIExpectResponseError(
            "Invalid response during Expect handling"
        ) from None


def _parse_expect_status_line(line):
    if not line or len(line) > _MAXLINE:
        raise _OCIExpectResponseError(
            "Incomplete response during Expect handling"
        )

    parts = line.rstrip(b"\r\n").split(None, 2)
    if (
        len(parts) < 2
        or not parts[0].startswith(b"HTTP/")
        or len(parts[1]) != 3
        or not parts[1].isdigit()
    ):
        raise _OCIExpectResponseError(
            "Invalid response during Expect handling"
        )

    try:
        version = parts[0].decode("ascii")
        status = int(parts[1])
        reason = parts[2].decode("iso-8859-1") if len(parts) == 3 else ""
    except (UnicodeDecodeError, ValueError):
        raise _OCIExpectResponseError(
            "Invalid response during Expect handling"
        ) from None

    if not 100 <= status <= 999:
        raise _OCIExpectResponseError(
            "Invalid response during Expect handling"
        )
    return version, status, reason


class _OCIExpectResponseReceived(Exception):
    """Stop urllib3 before it advances a body rejected by the service."""


class _OCIExpectResponseError(ProtocolError):
    """A sanitized failure while parsing an interim Expect response."""


class OCIHTTPResponse(HTTPResponse):

    def __init__(self, *args, **kwargs):
        self._status_tuple = kwargs.pop("status_tuple", None)
        HTTPResponse.__init__(self, *args, **kwargs)

    def _read_status(self):
        if self._status_tuple is not None:
            status_tuple = self._status_tuple
            self._status_tuple = None
            return status_tuple
        return HTTPResponse._read_status(self)

    def begin(self):
        HTTPResponse.begin(self)
        try:
            _validate_response_headers(self.msg)
        except HeaderParsingError:
            self.close()
            raise


try:
    # urllib3 1.26.x
    BaseHTTPSConnection = urllib3.connection.VerifiedHTTPSConnection
except AttributeError:
    # urllib3 2.x
    BaseHTTPSConnection = urllib3.connection.HTTPSConnection


class OCIConnection(BaseHTTPSConnection):
    """HTTPConnection with safe header parsing and 100 Continue support."""

    EXPECT_CONTINUE_TIMEOUT_SECONDS = 3
    MAX_INFORMATIONAL_RESPONSES = 5

    def __init__(self, *args, **kwargs):
        super(OCIConnection, self).__init__(*args, **kwargs)
        # urllib3 connect() expects assert_hostname/assert_fingerprint attrs to
        # exist on the connection object. Ensure compatibility across base
        # classes/versions where these may not be initialized.
        if not hasattr(self, "assert_hostname"):
            self.assert_hostname = kwargs.get("assert_hostname", None)
        if not hasattr(self, "assert_fingerprint"):
            self.assert_fingerprint = kwargs.get("assert_fingerprint", None)
        self._original_response_cls = OCIHTTPResponse
        self.response_class = self._original_response_cls
        self._response_received = False
        self._using_expect_header = False
        self.logger = logging.getLogger("{}.{}".format(__name__, id(self)))

    @staticmethod
    def _has_expect_continue(headers):
        for header, value in (headers or {}).items():
            if (
                str(header).lower() == "expect"
                and isinstance(value, str)
                and value.strip().lower() == "100-continue"
            ):
                return True
        return False

    def request(self, method, url, body=None, headers=None, *args, **kwargs):
        self._response_received = False
        self._using_expect_header = self._has_expect_continue(headers)
        self.response_class = self._original_response_cls
        try:
            return super(OCIConnection, self).request(
                method, url, body=body, headers=headers, *args, **kwargs
            )
        except _OCIExpectResponseReceived:
            return None
        except _OCIExpectResponseError:
            self.close()
            raise

    def endheaders(self, *args, **kwargs):
        super(OCIConnection, self).endheaders(*args, **kwargs)
        if self._response_received:
            raise _OCIExpectResponseReceived()

    def getresponse(self):
        try:
            return super(OCIConnection, self).getresponse()
        except HeaderParsingError:
            self.close()
            raise

    def _send_output(self, message_body=None, *args, **kwargs):
        self._buffer.extend((b"", b""))
        msg = _to_bytes(self._buffer)
        del self._buffer[:]

        if not self._using_expect_header and isinstance(message_body, bytes):
            msg += message_body
            message_body = None

        self.send(msg)

        if self._using_expect_header:
            if urllib3.util.wait_for_read(
                self.sock, self.EXPECT_CONTINUE_TIMEOUT_SECONDS
            ):
                self._handle_expect_response()
                return

        if message_body is not None:
            self.send(message_body)

    def _handle_expect_response(self):
        self.sock.settimeout(self.EXPECT_CONTINUE_TIMEOUT_SECONDS)
        fp = self.sock.makefile("rb", 0)
        try:
            informational_responses = 0
            while True:
                status_tuple = _parse_expect_status_line(
                    fp.readline(_MAXLINE + 1)
                )
                status = status_tuple[1]

                if status == 100:
                    _read_interim_headers(fp)
                    return

                if 100 <= status < 200:
                    _read_interim_headers(fp)
                    informational_responses += 1
                    if informational_responses >= self.MAX_INFORMATIONAL_RESPONSES:
                        raise _OCIExpectResponseError(
                            "Too many informational responses during Expect handling"
                        )
                    continue

                self.response_class = functools.partial(
                    OCIHTTPResponse, status_tuple=status_tuple
                )
                self._response_received = True
                return
        except _OCIExpectResponseError:
            raise
        except Exception:
            raise _OCIExpectResponseError(
                "Invalid response during Expect handling"
            ) from None
        finally:
            fp.close()
            self.sock.settimeout(self.timeout)

    def send(self, data):
        if self._response_received:
            return None
        return super(OCIConnection, self).send(data)
