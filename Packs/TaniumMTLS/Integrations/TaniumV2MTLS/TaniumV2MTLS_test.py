import http.server
import json
import re
import shutil
import ssl
import subprocess
import tempfile
import threading

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException

import TaniumV2MTLS
from TaniumV2MTLS import Client, get_question_result, get_action_result


def get_fetch_data():
    with open("test_data/action_results.json") as f:
        return json.loads(f.read())


BASE_URL = "https://test.com/"

parse_question_res = {
    "data": [
        {
            "from_canonical_text": 0,
            "group": {
                "and_flag": True,
                "deleted_flag": True,
                "filters": [
                    {
                        "all_times_flag": False,
                        "all_values_flag": False,
                        "delimiter": "",
                        "delimiter_index": 0,
                        "ignore_case_flag": True,
                        "max_age_seconds": 0,
                        "not_flag": False,
                        "operator": "RegexMatch",
                        "sensor": {"hash": 3409330187, "id": 3, "name": "Computer Name"},
                        "substring_flag": False,
                        "substring_length": 0,
                        "substring_start": 0,
                        "utf8_flag": False,
                        "value": ".*equals.*",
                        "value_type": "String",
                    }
                ],
                "not_flag": False,
                "sub_groups": [],
            },
            "question_text": 'Get Computer Name from all machines with Computer Name contains "equals"',
            "selects": [{"sensor": {"hash": 3409330187, "name": "Computer Name"}}],
            "sensor_references": [
                {"name": "Computer Name", "real_ms_avg": 0, "start_char": "4"},
                {"name": "Computer Name", "real_ms_avg": 0, "start_char": "41"},
            ],
        }
    ]
}

parse_question_Folder_Contents_res = {
    "data": [
        {
            "from_canonical_text": 0,
            "question_text": "Get Folder-Contents from all machines",
            "selects": [{"sensor": {"hash": 3881863289, "name": "Folder-Contents"}}],
            "sensor_references": [{"name": "Folder-Contents", "real_ms_avg": 53, "start_char": "4"}],
        },
        {
            "from_canonical_text": 0,
            "question_text": "Get Tanium File Contents from all machines",
            "selects": [{"sensor": {"hash": 4070262781, "name": "Tanium File Contents"}}],
            "sensor_references": [{"name": "Folder-Contents", "real_ms_avg": 53, "start_char": "4"}],
        },
    ]
}

sensor_res = {"data": {"parameter_definition": '{"parameters":[{"key":"folderPath"}]}'}}

CREATE_ACTION_BY_TARGET_GROUP_RES = {
    "package_spec": {"source_id": 12345},
    "name": "action-name via Demisto API",
    "target_group": {"name": "target-group-name"},
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

CREATE_ACTION_BY_HOST_RES = {
    "package_spec": {"source_id": 20},
    "name": "action-name via Demisto API",
    "target_group": {
        "and_flag": True,
        "deleted_flag": True,
        "filters": [
            {
                "all_times_flag": False,
                "all_values_flag": False,
                "delimiter": "",
                "delimiter_index": 0,
                "ignore_case_flag": True,
                "max_age_seconds": 0,
                "not_flag": False,
                "operator": "RegexMatch",
                "sensor": {"hash": 3409330187, "id": 3, "name": "Computer Name"},
                "substring_flag": False,
                "substring_length": 0,
                "substring_start": 0,
                "utf8_flag": False,
                "value": ".*equals.*",
                "value_type": "String",
            }
        ],
        "not_flag": False,
        "sub_groups": [],
    },
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

CREATE_ACTION_WITH_PARAMETERS_RES = {
    "package_spec": {
        "source_id": 12345,
        "parameters": [{"key": "$1", "value": "true"}, {"key": "$2", "value": "value"}, {"key": "$3", "value": "otherValue"}],
    },
    "name": "action-name via Demisto API",
    "target_group": {"name": "target-group-name"},
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

QUESTION_RESULTS_RAW = {
    "data": {
        "result_sets": [
            {
                "age": 0,
                "archived_question_id": 0,
                "cache_id": "3891494157",
                "columns": [
                    {"hash": 3409330187, "name": "Computer Name", "type": 1},
                    {"hash": 2801942354, "name": "IPv4 Address", "type": 5},
                    {"hash": 1092986182, "name": "Logged In Users", "type": 1},
                    {"hash": 0, "name": "Count", "type": 3},
                ],
                "estimated_total": 2,
                "mr_tested": 2,
                "rows": [
                    {
                        "cid": 2232836718,
                        "data": [[{"text": "host-name"}], [{"text": "127.0.0.1"}], [{"text": "[no results]"}], [{"text": "1"}]],
                        "id": 699534294,
                    }
                ],
            }
        ]
    }
}


QUESTION_RESULTS = [{"ComputerName": "host-name", "IPv4Address": "127.0.0.1", "Count": "1"}]


def test_create_action_body_by_target_group_name(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "SESSION-ID"}})
    requests_mock.get(BASE_URL + "packages/by-name/package-name", json={"data": {"id": 12345, "expire_seconds": 360}})

    body = client.build_create_action_body(
        False, "action-name", "", package_name="package-name", action_group_id=1, target_group_name="target-group-name"
    )

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_TARGET_GROUP_RES)

    assert res == body


def test_create_action_body_by_host(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.get(BASE_URL + "packages/20", json={"data": {"id": 12345, "expire_seconds": 360}})
    requests_mock.post(BASE_URL + "parse_question", json=parse_question_res)

    body = client.build_create_action_body(True, "action-name", "", package_id=20, action_group_id=1, hostname="host")

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_HOST_RES)

    assert res == body


def test_create_action_body_with_parameters(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.get(BASE_URL + "packages/by-name/package-name", json={"data": {"id": 12345, "expire_seconds": 360}})

    body = client.build_create_action_body(
        False,
        "action-name",
        "$1=true;$2=value;$3=otherValue",
        package_name="package-name",
        action_group_id=1,
        target_group_name="target-group-name",
    )

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_WITH_PARAMETERS_RES)

    assert res == body


def test_parse_question_results():
    client = Client(BASE_URL, "username", "password", "domain")
    results = client.parse_question_results(QUESTION_RESULTS_RAW, 95)
    assert results == QUESTION_RESULTS


def test_parse_question(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")
    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.post(BASE_URL + "parse_question", json=parse_question_Folder_Contents_res)
    requests_mock.get(BASE_URL + "sensors/by-name/Folder-Contents", json=sensor_res)

    results = client.parse_question(r"Get Folder-Contents[c:\] from all machines", "")
    assert results["selects"][0]["sensor"]["name"] == "Folder-Contents"
    assert results["selects"][0]["sensor"]["parameters"][0]["key"] == "||folderPath||"
    assert results["selects"][0]["sensor"]["parameters"][0]["value"] == "c:\\"


def test_get_question_result_invalid_input():
    client = Client(BASE_URL, "username", "password", "domain")
    data_args = {"completion-percentage": "0"}
    try:
        _, _, _ = get_question_result(client, data_args)
    except ValueError as e:
        assert str(e) == "completion-percentage argument is invalid, Please enter number between 1 to 100"


data_test_parse_action_parameters = [
    ("key1=value1", [{"key": "key1", "value": "value1"}]),
    ("key1=value1=value1", [{"key": "key1", "value": "value1=value1"}]),
    ("key1=value1=value1;key2=value2", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "value2"}]),
    ("key1=value1=value1;key2=valu;e2", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "valu;e2"}]),
    ("key1=value1=value1;key2=ab=;c", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "ab=;c"}]),
]


@pytest.mark.parametrize("parameters, accepted_result", data_test_parse_action_parameters)
def test_parse_action_parameters(parameters, accepted_result):
    """Tests parse_action_parameters function
    Given
        A string representing a key=value list separated by ';'
        1. parameters = 'key1=value1'
        2. parameters = 'key1=value1=value1'
        3. parameters = 'key1=value1=value1;key2=value2'
        4. parameters = 'key1=value1=value1;key2=valu;e2'
        5. parameters = key1=value1=value1;key2=ab=;c'

    When
        When calling the "parse_action_parameters" function to extract it to a dictionary
    Then
        validate that everything is extracted properly even if there is within the value "=" or ";"
        1. Ensure result = [{'key': 'key1', 'value': 'value1'}]
        2. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}]
        3. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'value2'}]
        4. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'valu;e2'}]
        5. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'ab=;c'}]
    """
    client = Client(BASE_URL, "username", "password", "domain")
    result = client.parse_action_parameters(parameters)
    assert result == accepted_result


def test_update_session(mocker):
    """
    Tests the authentication method, based on the instance configurations.
    Given:
        - A client created using username and password
        - A client created using an API token
    When:
        - calling the update_session() function of the client
    Then:
        - Verify that the session was created using basic authentication
        - Verify that the session was created using oauth authentication
    """
    client = Client(BASE_URL, username="abdc", password="1234", domain="domain", api_token="")
    mocker.patch.object(Client, "_http_request", return_value={"data": {"session": "basic authentication"}})
    client.update_session()
    assert client.session == "basic authentication"

    client = Client(BASE_URL, username="", password="", domain="domain", api_token="oauth authentication")
    client.update_session()
    assert client.session == "oauth authentication"


def test_get_action_result(mocker):
    """
    Tests the get action result method.
    Given:
        - Action ID to get information on.
    When:
        - calling the get_action_result() function.
    Then:
        - Verify that the human_readable was created as expected.
        - Verify that the outputs was created as expected.
        - Verify that the raw_response was created as expected.
    """
    client = Client(BASE_URL, "username", "password", "domain")
    data_args = {"id": "350385"}
    action_res = get_fetch_data()
    mocker.patch.object(Client, "do_request", return_value=action_res["action_raw_response"])
    human_readable, outputs, action_res_outputs = get_action_result(client, data_args)
    assert action_res_outputs == action_res["action_output"]
    assert outputs == action_res["action_output_res"]
    assert "### Device Statuses" in human_readable


""" MUTUAL TLS (mTLS fork) """

MTLS_CLIENT_COMMON_NAME = "xsoar-client"
MTLS_KEY_PASSPHRASE = "test-passphrase"


def pem_block(label: str, body: str, headers: str = "") -> str:
    """Builds a PEM block with 64-character lines (the markers are built here to keep them out of the source)."""
    lines = "\n".join(body[index : index + 64] for index in range(0, len(body), 64))
    return f"-----BEGIN {label}-----\n{headers}{lines}\n-----END {label}-----\n"


FAKE_CERTIFICATE = pem_block("CERTIFICATE", "MIIC" + "A" * 120)
FAKE_CA_CERTIFICATE = pem_block("CERTIFICATE", "MIIC" + "C" * 120)
FAKE_KEY_BODY = "MIIE" + "B" * 120
FAKE_KEY = pem_block("RSA PRIVATE KEY", FAKE_KEY_BODY)
LEGACY_ENCRYPTION_HEADERS = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"


@pytest.mark.parametrize(
    "credentials_params, expected",
    [
        pytest.param(
            ({"identifier": "user", "password": "pass", "credentials": {"sshkey": "PEM", "sshkeyPass": "secret"}},),
            ("PEM", "secret"),
            id="credential from the credentials store",
        ),
        pytest.param(({"credentials": {"certificate": "PEM"}},), ("PEM", ""), id="certificate key"),
        pytest.param(({"identifier": "user", "password": "pass"},), ("", ""), id="credentials typed in the instance"),
        pytest.param(({"credentials": {"sshkey": "", "sshkeyPass": ""}},), ("", ""), id="credential without certificate"),
        pytest.param((None,), ("", ""), id="no credentials"),
        pytest.param(
            ({"credentials": {"sshkey": " "}}, {"credentials": {"sshkey": "PEM"}}),
            ("PEM", ""),
            id="first credential with a certificate",
        ),
    ],
)
def test_get_client_certificate_params(credentials_params, expected):
    """
    Given: the credentials parameters of an instance.
    When: reading the client certificate.
    Then: the Certificate field and passphrase of the first credential having a certificate are returned.
    """
    assert TaniumV2MTLS.get_client_certificate_params(*credentials_params) == expected


@pytest.mark.parametrize(
    "certificate_field",
    [
        pytest.param(FAKE_CERTIFICATE + FAKE_KEY, id="certificate then key"),
        pytest.param(FAKE_KEY + FAKE_CERTIFICATE, id="key then certificate"),
        pytest.param((FAKE_CERTIFICATE + FAKE_KEY).replace("\n", "\r\n"), id="CRLF line breaks"),
        pytest.param((FAKE_CERTIFICATE + FAKE_KEY).replace("\n", " "), id="spaces instead of line breaks"),
        pytest.param((FAKE_CERTIFICATE + FAKE_KEY).replace("\n", "\\n"), id="escaped line breaks"),
        pytest.param(
            "\n  " + (FAKE_CERTIFICATE + FAKE_KEY).replace("-----BEGIN", "----BEGIN").replace("-----END", "----END") + "\n\n",
            id="four-dash markers and surrounding blank lines",
        ),
    ],
)
def test_build_client_certificate_pem(certificate_field):
    """
    Given: the Certificate field of a credential holding a certificate and its private key, pasted in various ways.
    When: building the PEM given to the TLS layer.
    Then: the certificate comes first, followed by the private key, with standard PEM line breaks.
    """
    assert TaniumV2MTLS.build_client_certificate_pem(certificate_field, "") == FAKE_CERTIFICATE + FAKE_KEY


def test_build_client_certificate_pem_keeps_the_certificate_chain():
    """
    Given: the Certificate field holding the client certificate, an intermediate CA certificate and the private key.
    When: building the PEM given to the TLS layer.
    Then: the certificates are kept in their order, followed by the private key.
    """
    certificate_field = FAKE_CERTIFICATE + FAKE_CA_CERTIFICATE + FAKE_KEY
    assert TaniumV2MTLS.build_client_certificate_pem(certificate_field, "") == certificate_field


def test_build_client_certificate_pem_keeps_legacy_encryption_headers():
    """
    Given: the Certificate field holding a legacy encrypted private key, pasted with spaces instead of line breaks.
    When: building the PEM given to the TLS layer.
    Then: the encryption headers of the key are restored on their own lines.
    """
    encrypted_key = pem_block("RSA PRIVATE KEY", FAKE_KEY_BODY, LEGACY_ENCRYPTION_HEADERS)
    certificate_field = (FAKE_CERTIFICATE + encrypted_key).replace("\n", " ")
    expected_pem = FAKE_CERTIFICATE + encrypted_key
    assert TaniumV2MTLS.build_client_certificate_pem(certificate_field, "passphrase") == expected_pem


@pytest.mark.parametrize(
    "certificate_field, passphrase, expected_error",
    [
        pytest.param(FAKE_KEY, "", "No CERTIFICATE block", id="no certificate"),
        pytest.param("not a certificate", "", "No CERTIFICATE block", id="no PEM content"),
        pytest.param(FAKE_CERTIFICATE, "", "found 0", id="no private key"),
        pytest.param(FAKE_CERTIFICATE + FAKE_KEY + FAKE_KEY, "", "found 2", id="two private keys"),
        pytest.param(
            FAKE_CERTIFICATE + pem_block("ENCRYPTED PRIVATE KEY", FAKE_KEY_BODY),
            "",
            "is encrypted",
            id="encrypted key without passphrase",
        ),
        pytest.param(
            FAKE_CERTIFICATE + pem_block("RSA PRIVATE KEY", FAKE_KEY_BODY, LEGACY_ENCRYPTION_HEADERS),
            "",
            "is encrypted",
            id="legacy encrypted key without passphrase",
        ),
        pytest.param(
            FAKE_CERTIFICATE + FAKE_KEY.replace("MIIE", "MI*E"), "", "PRIVATE KEY block .* not valid PEM", id="bad base64"
        ),
    ],
)
def test_build_client_certificate_pem_invalid_field(certificate_field, passphrase, expected_error):
    """
    Given: a Certificate field that does not hold a usable certificate and private key.
    When: building the PEM given to the TLS layer.
    Then: an actionable error is raised, without the content of the key.
    """
    with pytest.raises(DemistoException, match=expected_error) as error:
        TaniumV2MTLS.build_client_certificate_pem(certificate_field, passphrase)
    assert "B" * 64 not in str(error.value)


class ClientCertificateEchoHandler(http.server.BaseHTTPRequestHandler):
    """Answers GET requests with the common name of the client certificate, and POST requests with a session."""

    def do_GET(self):
        subject = dict(field[0] for field in self.connection.getpeercert()["subject"])
        self.send_json({"data": {"peer": subject["commonName"]}})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_json({"data": {"session": "test-session"}})

    def send_json(self, content: dict) -> None:
        body = json.dumps(content).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def mtls_pki(tmp_path_factory):
    """A test CA, a server certificate for localhost, and client certificates signed by the CA."""
    if not shutil.which("openssl"):
        pytest.skip("The openssl command is required to generate the test certificates.")
    pki = tmp_path_factory.mktemp("mtls_pki")

    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], cwd=pki, check=True, capture_output=True)

    (pki / "san.ext").write_text("subjectAltName=DNS:localhost\n")
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "1", "-subj", "/CN=CA",
    )  # fmt: skip
    for name, common_name in (("server", "localhost"), ("client", MTLS_CLIENT_COMMON_NAME), ("other", "other-client")):
        openssl(
            "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
            "-subj", f"/CN={common_name}",
        )  # fmt: skip
        openssl(
            "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", f"{name}.crt", "-days", "1", "-extfile", "san.ext",
        )  # fmt: skip
    try:
        openssl("rsa", "-in", "client.key", "-out", "client_rsa.key", "-traditional")
    except subprocess.CalledProcessError:  # OpenSSL 1.x writes this format by default, and has no -traditional option.
        openssl("rsa", "-in", "client.key", "-out", "client_rsa.key")
    openssl(
        "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-in", "client.key", "-out", "client_encrypted.key",
        "-passout", f"pass:{MTLS_KEY_PASSPHRASE}",
    )  # fmt: skip
    return pki


@pytest.fixture(scope="module")
def mtls_server(mtls_pki):
    """An HTTPS server that requires a client certificate signed by the test CA. Yields its URL."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(mtls_pki / "server.crt", mtls_pki / "server.key")
    context.load_verify_locations(mtls_pki / "ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ClientCertificateEchoHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"https://localhost:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def trust_test_ca(monkeypatch, mtls_pki):
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(mtls_pki / "ca.crt"))


@pytest.fixture
def mtls_temp_dir(monkeypatch, tmp_path):
    """Makes the integration write its temporary files in an empty directory. Returns the directory."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


def read_certificate_field(mtls_pki, certificate_file: str, key_file: str) -> str:
    """The Certificate field of a credential: the certificate followed by its private key."""
    return (mtls_pki / certificate_file).read_text() + (mtls_pki / key_file).read_text()


def create_mtls_client(base_url: str, certificate_field: str = "", passphrase: str = "", verify: bool = True):
    return TaniumV2MTLS.Client(
        base_url,
        "user",
        "password",
        "domain",
        verify=verify,
        client_certificate=certificate_field,
        client_certificate_passphrase=passphrase,
    )


@pytest.mark.parametrize(
    "key_file, passphrase, verify",
    [
        pytest.param("client_rsa.key", "", True, id="RSA private key"),
        pytest.param("client.key", "", True, id="PKCS#8 private key"),
        pytest.param("client_encrypted.key", MTLS_KEY_PASSPHRASE, True, id="encrypted private key"),
        pytest.param("client_encrypted.key", MTLS_KEY_PASSPHRASE, False, id="encrypted private key, trust any certificate"),
    ],
)
def test_mtls_request_presents_the_client_certificate(
    mtls_pki, mtls_server, trust_test_ca, mtls_temp_dir, key_file, passphrase, verify
):
    """
    Given: a server requiring a client certificate, and a Certificate field holding the certificate and its key.
    When: sending a request.
    Then: the server receives the client certificate, and no certificate file is left on disk.
    """
    client = create_mtls_client(mtls_server, read_certificate_field(mtls_pki, "client.crt", key_file), passphrase, verify)
    assert list(mtls_temp_dir.iterdir()) == []

    response = client._http_request("GET", "system_status")

    assert response == {"data": {"peer": MTLS_CLIENT_COMMON_NAME}}


@pytest.mark.parametrize(
    "trusted_ca_bundle, host, expected_error",
    [
        pytest.param("", "localhost", "CERTIFICATE_VERIFY_FAILED", id="server certificate from an untrusted CA"),
        pytest.param("ca.crt", "127.0.0.1", "match|mismatch", id="server certificate for another host name"),
    ],
)
def test_mtls_request_verifies_the_server_certificate(
    monkeypatch, mtls_pki, mtls_server, trusted_ca_bundle, host, expected_error
):
    """
    Given: a client certificate, and a server certificate that must not be trusted ('Trust any certificate' not selected).
    When: sending a request.
    Then: the request fails on the server certificate, as without a client certificate.
    """
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    if trusted_ca_bundle:
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(mtls_pki / trusted_ca_bundle))
    else:
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    certificate_field = read_certificate_field(mtls_pki, "client.crt", "client_rsa.key")
    client = create_mtls_client(mtls_server.replace("localhost", host), certificate_field)

    with pytest.raises(DemistoException, match=r"TLS handshake with the server failed \(client certificate presented\)") as error:
        client._http_request("GET", "system_status")
    assert re.search(expected_error, str(error.value), re.IGNORECASE)


def test_mtls_request_without_client_certificate(mtls_server, trust_test_ca):
    """
    Given: a server requiring a client certificate, and no Certificate field.
    When: sending a request.
    Then: the TLS error is reported as such, rather than as a server certificate issue.
    """
    client = create_mtls_client(mtls_server)
    with pytest.raises(DemistoException, match=r"TLS handshake with the server failed \(client certificate not configured\)"):
        client._http_request("GET", "system_status")


@pytest.mark.parametrize(
    "key_file, passphrase",
    [
        pytest.param("other.key", "", id="key of another certificate"),
        pytest.param("client_encrypted.key", "wrong-passphrase", id="wrong passphrase"),
    ],
)
def test_client_certificate_that_cannot_be_loaded(mtls_pki, mtls_temp_dir, key_file, passphrase):
    """
    Given: a Certificate field holding a certificate and a private key that cannot be used together.
    When: creating the client.
    Then: an actionable error is raised before any request, and no certificate file is left behind.
    """
    certificate_field = read_certificate_field(mtls_pki, "client.crt", key_file)
    with pytest.raises(DemistoException, match="cannot be loaded"):
        create_mtls_client("https://localhost", certificate_field, passphrase)
    assert list(mtls_temp_dir.iterdir()) == []


def test_main_presents_the_certificate_of_the_credential(monkeypatch, mtls_pki, mtls_server, trust_test_ca, mtls_temp_dir):
    """
    Given: an instance whose API token credential, from the credentials store, holds the certificate and key.
    When: running a command.
    Then: the requests present the client certificate, and the temporary certificate file is removed.
    """
    certificate_field = read_certificate_field(mtls_pki, "client.crt", "client_rsa.key")
    params = {
        "url": mtls_server,
        "credentials": {"identifier": "user", "password": "password"},
        "credentials_api_token": {"password": "", "credentials": {"sshkey": certificate_field}},
    }
    raw_responses = []
    monkeypatch.setattr(demisto, "params", lambda: params)
    monkeypatch.setattr(demisto, "command", lambda: "tn-get-system-status")
    monkeypatch.setattr(demisto, "args", dict)
    monkeypatch.setattr(
        TaniumV2MTLS, "get_system_status", lambda client, args: ("", {}, client.do_request("GET", "system_status"))
    )
    monkeypatch.setattr(
        TaniumV2MTLS,
        "return_outputs",
        lambda readable_output, outputs, raw_response: raw_responses.append(raw_response),
    )

    TaniumV2MTLS.main()

    assert raw_responses == [{"data": {"peer": MTLS_CLIENT_COMMON_NAME}}]
    assert list(mtls_temp_dir.iterdir()) == []
