import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os
import re
import ssl
import tempfile

import urllib3
from requests.adapters import HTTPAdapter
from requests.utils import DEFAULT_CA_BUNDLE_PATH
from urllib3.util.ssl_ import create_urllib3_context


""" IMPORTS """
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" GLOBALS/PARAMS """
GROUP_TYPES = {0: "Filter-based group", 1: "Action group", 2: "Action policy pair group", 3: "Ad hoc group", 4: "Manual group"}
DEMISTO_API_ACTION_NAME = "via Demisto API"
DEFAULT_COMPLETION_PERCENTAGE = "95"

""" MUTUAL TLS (mTLS fork) """
# [mTLS fork] This section is identical in the "Tanium v2 mTLS" and "Tanium Threat Response v2 mTLS" integrations.
# It presents the client certificate stored in the Certificate field of the credential to the server (mutual TLS).

PEM_BLOCK_PATTERN = re.compile(r"-+\s*BEGIN\s+([A-Z0-9 ]+?)\s*-+(.*?)-+\s*END\s+\1\s*-+", re.DOTALL)
PEM_ENCRYPTION_HEADER_PATTERN = re.compile(r"(Proc-Type|DEK-Info):\s*(\S+)")
PEM_BASE64_BODY_PATTERN = re.compile(r"[A-Za-z0-9+/]+={0,2}")
PEM_LINE_LENGTH = 64
CERTIFICATE_PEM_LABEL = "CERTIFICATE"
PRIVATE_KEY_PEM_LABEL_SUFFIX = "PRIVATE KEY"
ENCRYPTED_PRIVATE_KEY_PEM_LABEL = "ENCRYPTED PRIVATE KEY"
LEGACY_ENCRYPTED_KEY_HEADER = "Proc-Type: 4,ENCRYPTED"
CERTIFICATE_FIELD_FORMAT_HINT = (
    "The Certificate field of the credential must contain the client certificate followed by its private key, "
    "both in PEM format."
)
TLS_ERROR_HINT = (
    "If the error is about the client certificate (e.g. 'certificate required', 'unknown ca', 'bad certificate'), "
    "check the Certificate field of the credential selected in the instance. If it is about the server certificate "
    "(e.g. 'CERTIFICATE_VERIFY_FAILED'), trust the server CA or select 'Trust any certificate'."
)


class ClientCertificateAdapter(HTTPAdapter):
    """Transport adapter presenting the client certificate through its own SSL context.

    The certificate is loaded in an SSL context dedicated to this adapter, rather than passed to ``requests`` as a file:
    the certificate file can be removed right away, and the private key is never loaded in an SSL context shared with
    other sessions (some ``requests`` versions share a default SSL context between all sessions).

    :type ssl_context: ``ssl.SSLContext``
    :param ssl_context: The SSL context holding the client certificate.
    """

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)


def get_client_certificate_params(*credentials_params: dict | None) -> tuple[str, str]:
    """Returns the Certificate field and its passphrase from the first credential that has a certificate.

    The Certificate field is only passed to the integration when the instance uses a credential from the credentials
    store: the credential object is then available under ``<param>["credentials"]``, with the Certificate field in
    ``sshkey`` and its passphrase in ``sshkeyPass``.

    :type credentials_params: ``dict | None``
    :param credentials_params: The credentials (type 9) instance parameters, in order of precedence.

    :return: The Certificate field (empty if none is configured) and its passphrase.
    :rtype: ``tuple[str, str]``
    """
    for credentials_param in credentials_params:
        credential_object = (credentials_param or {}).get("credentials") or {}
        certificate = credential_object.get("sshkey") or credential_object.get("certificate") or ""
        if certificate.strip():
            return certificate, credential_object.get("sshkeyPass") or ""
    return "", ""


def canonicalize_pem_block(label: str, body: str) -> str:
    """Rebuilds a PEM block with standard line breaks.

    Pasted content can reach the integration with its line breaks altered (spaces, CRLF, escaped newlines), which
    OpenSSL cannot parse. The base64 body is re-wrapped and the headers of legacy encrypted keys are kept.

    :type label: ``str``
    :param label: The PEM label, e.g. CERTIFICATE.

    :type body: ``str``
    :param body: The content between the BEGIN and END lines of the block.

    :return: The PEM block, ending with a newline.
    :rtype: ``str``
    """
    headers = [f"{name}: {value}" for name, value in PEM_ENCRYPTION_HEADER_PATTERN.findall(body)]
    base64_body = "".join(PEM_ENCRYPTION_HEADER_PATTERN.sub("", body).split())
    if not PEM_BASE64_BODY_PATTERN.fullmatch(base64_body):
        raise DemistoException(f"The {label} block in the Certificate field of the credential is not valid PEM.")

    lines = [f"-----BEGIN {label}-----", *headers, *([""] if headers else [])]
    lines += [base64_body[index : index + PEM_LINE_LENGTH] for index in range(0, len(base64_body), PEM_LINE_LENGTH)]
    lines.append(f"-----END {label}-----")
    return "\n".join(lines) + "\n"


def validate_client_certificate_blocks(certificates: list[str], private_keys: list[tuple[str, str]], passphrase: str) -> None:
    """Fails with an actionable message when the Certificate field does not hold a usable certificate and key.

    :type certificates: ``list[str]``
    :param certificates: The CERTIFICATE blocks found in the field.

    :type private_keys: ``list[tuple[str, str]]``
    :param private_keys: The (label, block) of every private key block found in the field.

    :type passphrase: ``str``
    :param passphrase: The passphrase of the private key, if any.
    """
    if not certificates:
        raise DemistoException(
            f"No CERTIFICATE block found in the Certificate field of the credential. {CERTIFICATE_FIELD_FORMAT_HINT}"
        )
    if len(private_keys) != 1:
        raise DemistoException(
            f"Expected exactly one PRIVATE KEY block in the Certificate field of the credential, found {len(private_keys)}. "
            f"{CERTIFICATE_FIELD_FORMAT_HINT}"
        )
    key_label, key_block = private_keys[0]
    if (key_label == ENCRYPTED_PRIVATE_KEY_PEM_LABEL or LEGACY_ENCRYPTED_KEY_HEADER in key_block) and not passphrase:
        raise DemistoException(
            "The private key in the Certificate field of the credential is encrypted, but the credential has no passphrase. "
            "Store the key unencrypted, e.g.: openssl rsa -in encrypted_key.pem -out key.pem"
        )


def build_client_certificate_pem(certificate_field: str, passphrase: str) -> str:
    """Extracts the client certificate and its private key from the Certificate field of the credential.

    The field is expected to contain the certificate PEM block (optionally followed by intermediate CA certificates)
    and the private key PEM block (e.g. RSA PRIVATE KEY), in any order.

    :type certificate_field: ``str``
    :param certificate_field: The content of the Certificate field.

    :type passphrase: ``str``
    :param passphrase: The passphrase of the private key, if any.

    :return: The certificates followed by the private key, in PEM format.
    :rtype: ``str``
    """
    normalized_field = certificate_field.replace("\\r", "").replace("\\n", "\n")
    pem_blocks = [(label, canonicalize_pem_block(label, body)) for label, body in PEM_BLOCK_PATTERN.findall(normalized_field)]
    certificates = [block for label, block in pem_blocks if label == CERTIFICATE_PEM_LABEL]
    private_keys = [(label, block) for label, block in pem_blocks if label.endswith(PRIVATE_KEY_PEM_LABEL_SUFFIX)]
    validate_client_certificate_blocks(certificates, private_keys, passphrase)
    return "".join(certificates) + private_keys[0][1]


def create_client_certificate_ssl_context(pem: str, passphrase: str, verify: bool) -> ssl.SSLContext:
    """Creates an SSL context presenting the client certificate.

    The TLS layer only loads certificates from files: the PEM is written to a temporary file, readable by the current
    user only, which is removed as soon as it is loaded.

    :type pem: ``str``
    :param pem: The certificates followed by the private key, in PEM format.

    :type passphrase: ``str``
    :param passphrase: The passphrase of the private key, if any.

    :type verify: ``bool``
    :param verify: Whether to verify the server certificate ('Trust any certificate' not selected).

    :return: The SSL context.
    :rtype: ``ssl.SSLContext``
    """
    ssl_context = create_urllib3_context()
    if verify:
        ssl_context.load_verify_locations(DEFAULT_CA_BUNDLE_PATH)  # The CA bundle used by requests.
    else:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    file_descriptor, certificate_path = tempfile.mkstemp(prefix="tanium_mtls_", suffix=".pem")
    try:
        with os.fdopen(file_descriptor, "w") as certificate_file:
            certificate_file.write(pem)
        # An empty password (rather than None) prevents OpenSSL from ever prompting for one.
        ssl_context.load_cert_chain(certificate_path, password=passphrase or "")
    except ssl.SSLError as error:
        raise DemistoException(
            f"The client certificate in the Certificate field of the credential cannot be loaded ({error}). "
            "Check that the first certificate matches the private key, and that the passphrase is correct."
        ) from error
    finally:
        os.remove(certificate_path)
    return ssl_context


def build_tls_error_message(error: Exception, client_certificate_enabled: bool) -> str | None:
    """Builds an actionable message when a request failed during the TLS handshake.

    ``BaseClient`` reports every TLS failure as a server certificate issue, which hides client certificate issues.

    :type error: ``Exception``
    :param error: The error raised by the request.

    :type client_certificate_enabled: ``bool``
    :param client_certificate_enabled: Whether a client certificate was presented.

    :return: The message, or None if the error is not a TLS error.
    :rtype: ``str | None``
    """
    ssl_error = error if isinstance(error, requests.exceptions.SSLError) else getattr(error, "exception", None)
    if not isinstance(ssl_error, requests.exceptions.SSLError):
        return None
    client_certificate_state = "presented" if client_certificate_enabled else "not configured"
    return f"TLS handshake with the server failed (client certificate {client_certificate_state}): {ssl_error}\n{TLS_ERROR_HINT}"


class Client(BaseClient):
    def __init__(
        self,
        base_url,
        username,
        password,
        domain,
        api_token=None,
        client_certificate: str = "",
        client_certificate_passphrase: str = "",
        **kwargs,
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.session = ""
        self.api_token = api_token
        self.client_certificate_enabled = False
        self.check_authentication()
        super().__init__(base_url, **kwargs)
        # [mTLS fork] Must run after BaseClient.__init__, which creates the session.
        self.setup_client_certificate(client_certificate, client_certificate_passphrase)

    def setup_client_certificate(self, client_certificate: str, client_certificate_passphrase: str) -> None:
        """[mTLS fork] Makes every request of the session present the client certificate (mutual TLS).

        :type client_certificate: ``str``
        :param client_certificate: The Certificate field of the credential.

        :type client_certificate_passphrase: ``str``
        :param client_certificate_passphrase: The passphrase of the private key, if any.
        """
        if not client_certificate.strip():
            demisto.debug("No client certificate in the credential, mutual TLS is disabled.")
            return

        pem = build_client_certificate_pem(client_certificate, client_certificate_passphrase)
        ssl_context = create_client_certificate_ssl_context(pem, client_certificate_passphrase, verify=bool(self._verify))
        self._session.mount("https://", ClientCertificateAdapter(ssl_context))
        self.client_certificate_enabled = True
        demisto.debug("Mutual TLS enabled, the client certificate of the credential is presented to the server.")

    def _http_request(self, *args, **kwargs):
        """[mTLS fork] Reports TLS handshake failures with their actual cause."""
        try:
            return super()._http_request(*args, **kwargs)
        except (DemistoException, requests.exceptions.SSLError) as error:
            tls_error_message = build_tls_error_message(error, self.client_certificate_enabled)
            if tls_error_message:
                raise DemistoException(tls_error_message, error) from error
            raise

    def do_request(self, method, url_suffix, data=None):
        if not self.session:
            self.update_session()

        res = self._http_request(
            method,
            url_suffix,
            headers={"session": self.session},
            json_data=data,
            resp_type="response",
            ok_codes=[200, 400, 401, 403, 404],
        )

        if res.status_code == 401:
            if self.api_token:
                err_msg = (
                    "Unauthorized Error: please verify that the given API token is valid and that the IP of the "
                    "client is listed in the api_token_trusted_ip_address_list global setting.\n"
                )
            else:
                err_msg = ""
            try:
                err_msg += str(res.json())
            except ValueError:
                err_msg += str(res)
            return_error(err_msg)

        if res.status_code == 403:
            self.update_session()
            res = self._http_request(
                method, url_suffix, headers={"session": self.session}, json_data=data, ok_codes=[200, 400, 404]
            )
            return res

        if res.status_code == 404 or res.status_code == 400:
            raise requests.HTTPError(res.json().get("text"))

        return res.json()

    def update_session(self):
        if self.api_token:
            self.session = self.api_token
        elif self.username and self.password:
            body = {"username": self.username, "domain": self.domain, "password": self.password}

            res = self._http_request("POST", "session/login", json_data=body, ok_codes=[200])

            self.session = res.get("data").get("session")
        else:  # no API token and no credentials were provided, raise an error:
            return_error("Please provide either an API Token or Username & Password.")

        return self.session

    def login(self):
        return self.update_session()

    def check_authentication(self):
        """
        Check that the authentication process is valid, i.e. user provided either API token to use OAuth 2.0
        authentication or user provided Username & Password for basic authentication, but not both credentials and
        API token.
        """
        if self.username and self.password and self.api_token:
            return_error(
                "Please clear either the Credentials or the API Token fields.\n"
                "If you wish to use basic authentication please provide username and password, "
                "and leave the API Token field empty.\n"
                "If you wish to use OAuth 2 authentication, please provide an API Token and leave the "
                "Credentials and Password fields empty."
            )

    def parse_sensor_parameters(self, parameters):
        sensors = parameters.split(";")
        parameter_conditions = []

        for sensor in sensors:
            sensor_name = sensor.split("{")[0]
            tmp_item = {"sensor": sensor_name, "parameters": []}

            parameters_txt = sensor.split("{")[1][:-1]
            params = parameters_txt.split(",")
            for param in params:
                tmp_item["parameters"].append({"key": "||" + param.split("=")[0] + "||", "value": param.split("=")[1]})
            parameter_conditions.append(tmp_item)

        return parameter_conditions

    def parse_action_parameters(self, parameters: str) -> List[Any]:
        """
        Receives a string representing a key=value list separated by ';', and returns them as a list of dictionaries
        Args:
            parameters (str): string which contains keys and values

        Returns:
            parameter_conditions (List): list of dictionaries
        """
        parameters_list = parameters.split(";")
        parameter_conditions: List[dict[str, str]] = []
        add_to_the_previous_pram = ""
        # Goes over the parameters from the end and any param that does not contain a key and value is added to the previous param
        for param in reversed(parameters_list):
            param += add_to_the_previous_pram
            add_to_the_previous_pram = ""
            if "=" not in param or param.startswith("="):
                add_to_the_previous_pram = f";{param}"
                continue
            parameter_conditions.insert(0, {"key": param.split("=", 1)[0], "value": param.split("=", 1)[1]})
        return parameter_conditions

    def add_parameters_to_question(self, question_response, parameters):
        if not parameters:
            return question_response

        for item in question_response.get("selects"):
            sensor = item.get("sensor").get("name")

            for parameter in parameters:
                if parameter["sensor"] == sensor:
                    item["sensor"]["parameters"] = parameter["parameters"]
                    item["sensor"]["source_hash"] = item["sensor"]["hash"]
                    del item["sensor"]["hash"]

        return question_response

    def parse_question(self, text, parameters):
        parameters_condition = []  # type: ignore

        if parameters:
            try:
                parameters_condition = self.parse_sensor_parameters(parameters)
            except Exception:
                raise ValueError("Failed to parse question parameters.")

            res = self.do_request("POST", "parse_question", {"text": text}).get("data")[0]
        else:
            # if there are no parameters argument - try to gets the sensors from parse question api
            # for example, if the input text question is: `Get Folder Contents[c:\] from all machines`
            # after the regex is: `Get Folder Contents from all machines`
            text_without_params = re.sub(r"\[(.*?)\]", "", text)
            res = self.do_request("POST", "parse_question", {"text": text_without_params}).get("data")[0]

            # call sensors/by-name/ for each sensor in the response and update parameters_condition
            # with the correct parameters
            for item in res.get("selects", []):
                sensor = item.get("sensor", {}).get("name")
                search_results = re.search(rf"{sensor}\[(.*)\]", text)
                if search_results:
                    parameters_str = search_results.group(1)
                    parameters = parameters_str.split(",")
                    endpoint_url = f"sensors/by-name/{sensor}"
                    sensor_response = self.do_request("GET", endpoint_url)
                    sensor_response = self.get_sensor_item(sensor_response.get("data"))

                    tmp_item = {"sensor": sensor, "parameters": []}
                    for param, sensor_key in zip(parameters, sensor_response["Parameters"]):
                        if param:
                            if param == '""':
                                param = ""
                            tmp_item["parameters"].append({"key": "||" + sensor_key["Key"] + "||", "value": param})
                    parameters_condition.append(tmp_item)

        res = self.add_parameters_to_question(res, parameters_condition)
        return res

    def create_question(self, question_body):
        res = self.do_request("POST", "questions", question_body)
        return res.get("data").get("id"), res

    def parse_question_results(self, result, completion_percentage):
        results_sets = result.get("data").get("result_sets")[0]
        estimated_total = results_sets.get("estimated_total")
        mr_tested = results_sets.get("mr_tested")

        if not estimated_total and not mr_tested:
            return None

        percentage = mr_tested / estimated_total * 100

        if percentage < completion_percentage:
            return None
        if results_sets.get("row_count") == 0:
            return []

        rows = []
        columns = []
        for column in results_sets.get("columns"):
            columns.append(column.get("name").replace(" ", ""))

        for row in results_sets.get("rows"):
            tmp_row = {}
            for item, column in zip(row.get("data", []), columns):
                item_value_lst = [x.get("text", "") for x in item]
                if "[current result unavailable]" in item_value_lst:
                    break
                item_value = ", ".join(item_value_lst)

                if item_value != "[no results]":
                    tmp_row[column] = item_value
            rows.append(tmp_row)

        return rows

    def update_id(self, obj):
        if "id" in obj:
            obj["ID"] = obj["id"]
            del obj["id"]
            return obj
        return obj

    def build_create_action_body(
        self,
        by_host,
        action_name,
        parameters,
        package_id="",
        package_name="",
        action_group_id="",
        action_group_name="",
        target_group_id="",
        target_group_name="",
        hostname="",
        ip_address="",
        expire=None,
    ):
        """
        This method used to build create_action request body by host or by target group
        """

        # package and action group are mandatory and can be pass by name or id
        if not package_id and not package_name:
            raise ValueError("package id and package name are missing, Please specify one of them.")
        if not action_group_id and not action_group_name:
            raise ValueError("action group id and action group name are missing, Please specify one of them.")

        if action_name:
            action_name = f"{action_name} {DEMISTO_API_ACTION_NAME}"
        else:
            action_name = DEMISTO_API_ACTION_NAME

        # get package expire_seconds value
        if package_id:
            get_package_res = self.do_request("GET", "packages/" + str(package_id))
        elif package_name:
            get_package_res = self.do_request("GET", "packages/by-name/" + package_name)
            package_id = get_package_res.get("data").get("id")

        expire_seconds = expire if expire else get_package_res.get("data").get("expire_seconds", 0)

        target_group = {}  # type: ignore

        if by_host:
            # use Tanium parse question request to set target group by hostname or ip address
            if not ip_address and not hostname:
                raise ValueError("hostname and ip address are missing, Please specify one of them.")

            group_question = ""
            demisto.debug(f"Initializing {group_question=}")
            if ip_address:
                group_question = f"Get Computer Name from all machines with ip address equals {ip_address}"
            if hostname:
                group_question = f"Get Computer Name from all machines with Computer Name equals {hostname}"

            group_res = self.parse_question(group_question, None)
            target_group = group_res.get("group")

            if not target_group:
                raise ValueError("Failed to parse target group question")
        else:
            # set target group by id or name
            if not target_group_id and not target_group_name:
                raise ValueError("target group id and target group name are missing, Please specify one of them.")

            if target_group_id:
                target_group = {"id": target_group_id}
            if target_group_name:
                target_group = {"name": target_group_name}

        action_group = {}  # type: ignore
        if action_group_id:
            action_group = {"id": action_group_id}
        if action_group_name:
            action_group = {"name": action_group_name}

        parameters_condition = []  # type: ignore
        if parameters:
            # build action parameters object
            try:
                parameters_condition = self.parse_action_parameters(parameters)
            except Exception:
                raise ValueError("Failed to parse action parameters.")

        # crete the body of the response
        body = {"package_spec": {"source_id": package_id}}

        if parameters_condition:
            # set the parameters value to request body
            body["package_spec"]["parameters"] = []
            for param in parameters_condition:
                body["package_spec"]["parameters"].append(param)

        body["name"] = action_name
        body["target_group"] = target_group
        body["action_group"] = action_group
        body["expire_seconds"] = expire_seconds

        return body

    def get_package_item(self, package):
        item = {
            "ContentSet": {},
            "ModUser": {},
            "Command": package.get("command"),
            "CommandTimeout": package.get("command_timeout"),
            "CreationTime": package.get("creation_time"),
            "DisplayName": package.get("display_name"),
            "ExpireSeconds": package.get("expire_seconds"),
            "ID": package.get("id"),
            "LastModifiedBy": package.get("last_modified_by"),
            "LastUpdate": package.get("last_update"),
            "ModificationTime": package.get("modification_time"),
            "Name": package.get("name"),
            "SourceId": package.get("source_id"),
            "VerifyExpireSeconds": package.get("verify_expire_seconds"),
            "Parameters": self.get_parameter_item(package),
        }

        content_set = package.get("content_set")
        if content_set:
            item["ContentSet"]["Id"] = content_set.get("id")
            item["ContentSet"]["Name"] = content_set.get("name")

        mod_user = package.get("ModUser")
        if mod_user:
            item["ModUser"]["Domain"] = mod_user.get("domain")
            item["ModUser"]["Id"] = mod_user.get("id")
            item["ModUser"]["Name"] = mod_user.get("name")

        files = package.get("files")
        files_list = []
        if files:
            for file in files:
                files_list.append({"ID": file.get("id"), "Hash": file.get("hash"), "Name": file.get("name")})

        item["Files"] = files_list
        return item

    def get_question_item(self, question):
        item = {
            "ID": question.get("id"),
            "Expiration": question.get("expiration"),
            "ExpireSeconds": question.get("expire_seconds"),
            "ForceComputerIdFlag": question.get("force_computer_id_flag"),
            "IsExpired": question.get("is_expired"),
            "QueryText": question.get("query_text"),
        }

        saved_question_id = (question.get("saved_question") or {}).get("id")
        if saved_question_id:
            item["SavedQuestionId"] = saved_question_id

        user = question.get("user")
        if user:
            item["UserId"] = user.get("id")
            item["UserName"] = user.get("name")
        return item

    def get_saved_question_item(self, question):
        item = {
            "ArchiveEnabledFlag": question.get("archive_enabled_flag"),
            "ArchiveOwner": question.get("archive_owner"),
            "ExpireSeconds": question.get("expire_seconds"),
            "ID": question.get("id"),
            "IssueSeconds": question.get("issue_seconds"),
            "IssueSecondsNeverFlag": question.get("issue_seconds_never_flag"),
            "KeepSeconds": question.get("keep_seconds"),
            "ModTime": question.get("mod_time"),
            "MostRecentQuestionId": question.get("most_recent_question_id"),
            "Name": question.get("name"),
            "QueryText": question.get("query_text"),
            "QuestionId": question.get("question").get("id"),
            "RowCountFlag": question.get("row_count_flag"),
            "SortColumn": question.get("sort_column"),
        }

        mod_user = question.get("ModUser")
        if mod_user:
            item["ModUserDomain"] = mod_user.get("domain")
            item["ModUserId"] = mod_user.get("id")
            item["ModUserName"] = mod_user.get("name")

        user = question.get("user")
        if user:
            item["UserId"] = user.get("id")
            item["UserName"] = user.get("name")
        return item

    def get_sensor_item(self, sensor):
        item = {
            "Category": sensor.get("category", ""),
            "CreationTime": sensor.get("creation_time", ""),
            "Description": sensor.get("description", ""),
            "Hash": sensor.get("hash", ""),
            "ID": sensor.get("id", ""),
            "IgnoreCaseFlag": sensor.get("ignore_case_flag", ""),
            "KeepDuplicatesFlag": sensor.get("keep_duplicates_flag", ""),
            "LastModifiedBy": sensor.get("last_modified_by", ""),
            "MaxAgeSeconds": sensor.get("max_age_seconds", ""),
            "ModificationTime": sensor.get("modification_time", ""),
            "Name": sensor.get("name", ""),
            "SourceId": sensor.get("source_id", ""),
            "Parameters": self.get_parameter_item(sensor),
        }

        content_set = sensor.get("content_set")
        if content_set:
            item["ContentSetId"] = content_set.get("id")
            item["ContentSetName"] = content_set.get("name")

        mod_user = sensor.get("mod_user")
        if mod_user:
            item["ModUserDomain"] = mod_user.get("domain")
            item["ModUserId"] = mod_user.get("id")
            item["ModUserName"] = mod_user.get("name")

        return item

    def get_parameter_item(self, sensor):
        parameters = sensor.get("parameter_definition")
        params_list = []
        if parameters:
            try:
                parameters = json.loads(parameters).get("parameters")
            except ValueError:
                return {"Value": parameters}
            for param in parameters:
                params_list.append(
                    {
                        "Key": param.get("key"),
                        "Label": param.get("label"),
                        "Values": param.get("values"),
                        "ParameterType": param.get("parameterType"),
                    }
                )

        return params_list

    def get_action_item(self, action):
        item = {
            "ActionGroupId": action.get("action_group").get("id"),
            "ActionGroupName": action.get("action_group").get("name"),
            "CreationTime": action.get("creation_time"),
            "ExpirationTime": action.get("expiration_time"),
            "ExpireSeconds": action.get("expire_seconds"),
            "HistorySavedQuestionId": action.get("history_saved_question").get("id"),
            "ID": action.get("id"),
            "Name": action.get("name"),
            "PackageId": action.get("package_spec").get("id"),
            "PackageName": action.get("package_spec").get("name"),
            "SavedActionId": action.get("saved_action").get("id"),
            "StartTime": action.get("start_time"),
            "Status": action.get("status"),
            "StoppedFlag": action.get("stopped_flag"),
            "TargetGroupId": action.get("target_group").get("id"),
            "TargetGroupName": action.get("target_group").get("name"),
        }

        user = action.get("user")
        if user:
            item["UserDomain"] = user.get("domain")
            item["UserId"] = user.get("id")
            item["UserName"] = user.get("name")

        approver = action.get("approver")
        if approver:
            item["ApproverId"] = approver.get("id")
            item["ApproverName"] = approver.get("name")

        return item

    def get_saved_action_item(self, action):
        item = {
            "ActionGroupId": action.get("action_group_id"),
            "ApprovedFlag": action.get("approved_flag"),
            "ApproverId": action.get("approver").get("id"),
            "ApproverName": action.get("approver").get("name"),
            "CreationTime": action.get("creation_time"),
            "EndTime": action.get("end_time"),
            "ExpireSeconds": action.get("expire_seconds"),
            "ID": action.get("id"),
            "LastActionId": action.get("last_action").get("id"),
            "LastActionStartTime": action.get("last_action").get("start_time"),
            "TargetGroupId": action.get("target_group").get("id"),
            "LastStartTime": action.get("last_start_time"),
            "Name": action.get("name"),
            "NextStartTime": action.get("next_start_time"),
            "StartTime": action.get("start_time"),
            "Status": action.get("status"),
            "UserId": action.get("user").get("id"),
            "UserName": action.get("user").get("name"),
        }

        package_spec = action.get("package_spec")
        if package_spec:
            item["PackageId"] = package_spec.get("id")
            item["PackageName"] = package_spec.get("name")
            item["PackageSourceHash"] = package_spec.get("source_hash")

        return item

    def get_saved_action_pending_item(self, action):
        return {
            "ApprovedFlag": action.get("approved_flag"),
            "ID": action.get("id"),
            "Name": action.get("name"),
            "OwnerUserId": action.get("owner_user_id"),
        }

    def get_host_item(self, client):
        return {
            "ComputerId": client.get("computer_id"),
            "FullVersion": client.get("full_version"),
            "HostName": client.get("host_name"),
            "IpAddressClient": client.get("ipaddress_client"),
            "IpAddressServer": client.get("ipaddress_server"),
            "LastRegistration": client.get("last_registration"),
            "Status": client.get("status"),
        }

    def get_group_item(self, group):
        item = {"ID": group.get("id"), "Name": group.get("name"), "Deleted": group.get("deleted_flag"), "Text": group.get("text")}
        group_type = group.get("type")

        if group_type:
            item["Type"] = GROUP_TYPES[group_type]
        else:
            item["Type"] = "Manual group"

        return item


""" COMMANDS + REQUESTS FUNCTIONS """


def test_module(client, data_args):
    if client.do_request("GET", "system_status"):
        return demisto.results("ok")
    raise ValueError("Test Tanium integration failed - please check your username and password")


def get_system_status(client, data_args):
    raw_response = client.do_request("GET", "system_status")
    response = raw_response.get("data")

    context = []
    for item in response:
        if item.get("computer_id"):
            context.append(client.get_host_item(item))

    context = createContext(context, removeNull=True)
    outputs = {"Tanium.Client(val.ComputerId && val.ComputerId === obj.ComputerId)": context}
    human_readable = tableToMarkdown("System status", context)
    return human_readable, outputs, raw_response


def get_package(client, data_args):
    id_ = data_args.get("id")
    name = data_args.get("name")
    endpoint_url = ""
    if not id_ and not name:
        raise ValueError("id and name arguments are missing, Please specify one of them.")
    if name:
        endpoint_url = "packages/by-name/" + name
    if id_:
        endpoint_url = "packages/" + str(id_)

    raw_response = client.do_request("GET", endpoint_url)
    package = client.get_package_item(raw_response.get("data"))
    params = package.get("Parameters")
    files = package.get("Files")

    context = createContext(package, removeNull=True)
    outputs = {"TaniumPackage(val.ID && val.ID === obj.ID)": context}

    del package["Parameters"]
    del package["Files"]

    human_readable = tableToMarkdown("Package information", package)
    human_readable += tableToMarkdown("Parameters information", params)
    human_readable += tableToMarkdown("Files information", files)
    return human_readable, outputs, raw_response


def create_package(client, data_args):
    name = data_args.get("name")
    command = data_args.get("command")
    body = {"name": name, "command": command}

    raw_response = client.do_request("POST", "packages", body)
    package = client.get_package_item(raw_response.get("data"))

    params = package.get("Parameters")
    files = package.get("Files")

    context = createContext(package, removeNull=True)
    outputs = {"TaniumPackage(val.ID && val.ID === obj.ID)": context}

    human_readable = tableToMarkdown("Package information", package)
    human_readable += tableToMarkdown("Parameters information", params)
    human_readable += tableToMarkdown("Files information", files)
    return human_readable, outputs, raw_response


def get_packages(client, data_args):
    count = int(data_args.get("limit"))
    raw_response = client.do_request("GET", "packages")
    packages = []

    # ignoring the last item because its not a package object
    for package in raw_response.get("data", [])[:-1][:count]:
        package = client.get_package_item(package)

        del package["Files"]
        del package["Parameters"]
        packages.append(package)

    context = createContext(packages, removeNull=True)
    outputs = {"TaniumPackage(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Packages", packages)
    return human_readable, outputs, raw_response


def get_sensor(client, data_args):
    id_ = data_args.get("id")
    name = data_args.get("name")
    endpoint_url = ""
    if not id_ and not name:
        raise ValueError("id and name arguments are missing, Please specify one of them.")
    if name:
        endpoint_url = "sensors/by-name/" + name
    if id_:
        endpoint_url = "sensors/" + str(id_)

    raw_response = client.do_request("GET", endpoint_url)
    sensor = client.get_sensor_item(raw_response.get("data"))

    context = createContext(sensor, removeNull=True)
    outputs = {"TaniumSensor(val.ID && val.ID === obj.ID)": context}

    params = sensor["Parameters"]
    del sensor["Parameters"]

    human_readable = tableToMarkdown("Sensor information", sensor)
    human_readable += tableToMarkdown("Parameter information", params)
    return human_readable, outputs, raw_response


def get_sensors(client, data_args):
    count = int(data_args.get("limit"))
    res = client.do_request("GET", "sensors/")

    sensors = []
    # ignoring the last item because its not a sensor object
    for sensor in res.get("data", [])[:-1][:count]:
        sensor = client.get_sensor_item(sensor)
        del sensor["Parameters"]
        sensors.append(sensor)

    context = createContext(sensors, removeNull=True)
    outputs = {"TaniumSensor(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Sensors", sensors)
    return human_readable, outputs, res


def ask_question(client, data_args):
    question_text = data_args.get("question-text")
    parameters = data_args.get("parameters")

    if parameters:
        body = client.parse_question(question_text, parameters)
        id_, res = client.create_question(body)
    else:
        res = client.do_request("POST", "questions", {"query_text": question_text})
        id_ = res.get("data").get("id")

    context = {"ID": id_}
    context = createContext(context, removeNull=True)
    outputs = {"Tanium.Question(val.ID && val.ID === obj.ID)": context}
    return f"New question created. ID = {str(id_)}", outputs, res


def get_question_metadata(client, data_args):
    id_ = data_args.get("question-id")
    raw_response = client.do_request("GET", "questions/" + str(id_))
    question_data = raw_response.get("data")
    question_data = client.get_question_item(question_data)

    context = createContext(question_data, removeNull=True)
    outputs = {"Tanium.Question(val.Tanium.ID && val.Tanium.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Question results", question_data)
    return human_readable, outputs, raw_response


def get_question_result(client, data_args):
    id_ = data_args.get("question-id")
    completion_percentage = int(data_args.get("completion-percentage", DEFAULT_COMPLETION_PERCENTAGE))
    if completion_percentage > 100 or completion_percentage < 1:
        raise ValueError("completion-percentage argument is invalid, Please enter number between 1 to 100")

    res = client.do_request("GET", "result_data/question/" + str(id_))

    rows = client.parse_question_results(res, completion_percentage)

    if rows is None:
        context = {"QuestionID": id_, "Status": "Pending"}
        return (
            f"Question is still executing, Question id: {str(id_)}",
            {f"Tanium.QuestionResult(val.QuestionID == {id_})": context},
            res,
        )

    context = {"QuestionID": id_, "Status": "Completed", "Results": rows}
    context = createContext(context, removeNull=True)
    outputs = {f"Tanium.QuestionResult(val.QuestionID == {id_})": context}
    human_readable = tableToMarkdown("Question results", rows)
    return human_readable, outputs, res


def create_saved_question(client, data_args):
    id_ = data_args.get("question-id")
    name = data_args.get("name")
    body = {"name": name, "question": {"id": id_}}
    raw_response = client.do_request("POST", "saved_questions", body)

    response = raw_response.get("data")
    response = client.update_id(response)

    context = createContext(response, removeNull=True)
    outputs = {"Tanium.SavedQuestion(val.ID && val.ID === obj.ID)": context}
    saved_question_id = str(response["ID"])
    return f"Question saved. ID = {saved_question_id}", outputs, raw_response


def get_saved_question_metadata(client, data_args):
    id_ = data_args.get("question-id")
    name = data_args.get("question-name")
    endpoint_url = ""
    if not id_ and not name:
        raise ValueError("question id and question name arguments are missing, Please specify one of them.")
    if name:
        endpoint_url = "saved_questions/by-name/" + name
    if id_:
        endpoint_url = "saved_questions/" + str(id_)

    raw_response = client.do_request("GET", endpoint_url)
    response = client.get_saved_question_item(raw_response.get("data"))

    context = createContext(response, removeNull=True)
    outputs = {"Tanium.SavedQuestion(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved question information", context)
    return human_readable, outputs, raw_response


def get_saved_question_result(client, data_args):
    id_ = data_args.get("question-id")
    completion_percentage = int(data_args.get("completion-percentage", DEFAULT_COMPLETION_PERCENTAGE))
    if completion_percentage > 100 or completion_percentage < 1:
        raise ValueError("completion-percentage argument is invalid, Please enter number between 1 to 100")

    res = client.do_request("GET", "result_data/saved_question/" + str(id_))

    rows = client.parse_question_results(res, completion_percentage)
    if rows is None:
        context = {"SavedQuestionID": id_, "Status": "Pending"}
        return (
            f"Question is still executing, Question id: {str(id_)}",
            {f"Tanium.SavedQuestionResult(val.SavedQuestionID == {id_})": context},
            res,
        )

    context = {"SavedQuestionID": id_, "Status": "Completed", "Results": rows}
    context = createContext(context, removeNull=True)
    outputs = {f"Tanium.SavedQuestionResult(val.SavedQuestionID == {id_})": context}
    human_readable = tableToMarkdown("question results:", rows)
    return human_readable, outputs, res


def get_saved_questions(client, data_args):
    count = int(data_args.get("limit"))
    raw_response = client.do_request("GET", "saved_questions")

    questions = []
    # ignoring the last item because its not a saved question object
    for question in raw_response.get("data", [])[:-1][:count]:
        question = client.get_saved_question_item(question)
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {"Tanium.SavedQuestion(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved questions", questions)
    return human_readable, outputs, raw_response


def create_action(client, data_args):
    action_name = data_args.get("action-name")
    package_id = data_args.get("package-id")
    package_name = data_args.get("package-name")
    target_group_id = data_args.get("target-group-id")
    target_group_name = data_args.get("target-group-name")
    action_group_id = data_args.get("action-group-id")
    action_group_name = data_args.get("action-group-name")
    parameters = data_args.get("parameters")

    body = client.build_create_action_body(
        False,
        action_name,
        parameters,
        package_id=package_id,
        package_name=package_name,
        action_group_id=action_group_id,
        action_group_name=action_group_name,
        target_group_id=target_group_id,
        target_group_name=target_group_name,
    )

    raw_response = client.do_request("POST", "actions", body)
    action = client.get_action_item(raw_response.get("data"))

    context = createContext(action, removeNull=True)
    outputs = {"Tanium.Action(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Action created", action)
    return human_readable, outputs, raw_response


def create_action_by_host(client, data_args):
    action_name = data_args.get("action-name")
    package_id = data_args.get("package-id")
    package_name = data_args.get("package-name")
    action_group_id = data_args.get("action-group-id")
    action_group_name = data_args.get("action-group-name")
    parameters = data_args.get("parameters")
    ip_address = data_args.get("ip-address")
    hostname = data_args.get("hostname")
    expire = arg_to_number(data_args.get("expiration-time"))

    body = client.build_create_action_body(
        True,
        action_name,
        parameters,
        package_id=package_id,
        package_name=package_name,
        action_group_id=action_group_id,
        action_group_name=action_group_name,
        hostname=hostname,
        ip_address=ip_address,
        expire=expire,
    )

    raw_response = client.do_request("POST", "actions", body)
    action = client.get_action_item(raw_response.get("data"))

    context = createContext(action, removeNull=True)
    outputs = {"Tanium.Action(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Action created", action)
    return human_readable, outputs, raw_response


def get_action(client, data_args):
    id_ = data_args.get("id")
    raw_response = client.do_request("GET", "actions/" + str(id_))
    action = raw_response.get("data")
    action = client.get_action_item(action)

    context = createContext(action, removeNull=True)
    outputs = {"Tanium.Action(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Action information", action)
    return human_readable, outputs, raw_response


def get_actions(client, data_args):
    count = int(data_args.get("limit"))
    raw_response = client.do_request("GET", "actions")

    actions = []
    # ignoring the last item because its not action object
    for action in raw_response.get("data", [])[:-1][:count]:
        action = client.get_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {"Tanium.Action(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Actions", actions)
    return human_readable, outputs, raw_response


def create_saved_action(client, data_args):
    action_group_id = data_args.get("action-group-id")
    package_id = data_args.get("package-id")
    name = data_args.get("name")

    body = {"name": name, "action_group": {"id": action_group_id}, "package_spec": {"id": package_id}}
    raw_response = client.do_request("POST", "saved_actions", body)
    response = client.get_saved_action_item(raw_response.get("data"))

    context = createContext(response, removeNull=True)
    outputs = {"Tanium.SavedAction(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved action created", context)
    return human_readable, outputs, raw_response


def get_saved_action(client, data_args):
    id_ = data_args.get("id")
    name = data_args.get("name")
    endpoint_url = ""
    if not id_ and not name:
        raise ValueError("id and name arguments are missing, Please specify one of them.")
    if name:
        endpoint_url = "saved_actions/by-name/" + name
    if id_:
        endpoint_url = "saved_actions/" + str(id_)

    raw_response = client.do_request("GET", endpoint_url)
    response = client.get_saved_action_item(raw_response.get("data"))

    context = createContext(response, removeNull=True)
    outputs = {"Tanium.SavedAction(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved action information", context)
    return human_readable, outputs, raw_response


def get_saved_actions(client, data_args):
    count = int(data_args.get("limit"))
    raw_response = client.do_request("GET", "saved_actions")

    actions = []
    # ignoring the last item because its not a saved action object
    for action in raw_response.get("data", [])[:-1][:count]:
        action = client.get_saved_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {"Tanium.SavedAction(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved actions", actions)
    return human_readable, outputs, raw_response


def get_saved_actions_pending(client, data_args):
    count = int(data_args.get("limit"))
    raw_response = client.do_request("GET", "saved_action_approvals")

    actions = []
    for action in raw_response.get("data", [])[:count]:
        action = client.get_saved_action_pending_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {"Tanium.PendingSavedAction(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Saved actions pending approval", actions)
    return human_readable, outputs, raw_response


def create_manual_group(client, data_args):
    group_name = data_args.get("group-name")
    hosts = data_args.get("computer-names")
    ip_addresses = data_args.get("ip-addresses")

    if not ip_addresses and not hosts:
        raise ValueError("computer-names and ip-addresses arguments are missing, Please specify one of them.")

    body = {"name": group_name}

    hosts_list = []
    ips_list = []

    if hosts:
        hosts = hosts.split(",")
        for host in hosts:
            hosts_list.append({"computer_name": host})

    if ip_addresses:
        ip_addresses = ip_addresses.split(",")
        for ip in ip_addresses:
            ips_list.append({"ip_address": ip})

    body["computer_specs"] = hosts_list
    body["computer_specs"].extend(ips_list)

    raw_response = client.do_request("POST", "computer_groups", body)
    group = raw_response.get("data")
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {"Tanium.Group(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Group created", context)
    return human_readable, outputs, raw_response


def create_filter_based_group(client, data_args):
    group_name = data_args.get("group-name")
    text_filter = data_args.get("text-filter")

    body = {"name": group_name, "text": text_filter}

    raw_response = client.do_request("POST", "groups", body)
    group = raw_response.get("data")
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {"Tanium.Group(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Group created", context)
    return human_readable, outputs, raw_response


def get_group(client, data_args):
    id_ = data_args.get("id")
    name = data_args.get("name")
    endpoint_url = ""
    if not id_ and not name:
        raise ValueError("id and name arguments are missing, Please specify one of them.")
    if name:
        endpoint_url = "groups/by-name/" + name
    if id_:
        endpoint_url = "groups/" + str(id_)

    raw_response = client.do_request("GET", endpoint_url)
    group = raw_response.get("data")
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {"Tanium.Group(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Group information", group)
    return human_readable, outputs, raw_response


def get_groups(client, data_args):
    count = int(data_args.get("limit"))
    groups = []

    raw_response = client.do_request("GET", "groups")
    # ignoring the last item because its not a group object
    for group in raw_response.get("data", [])[:-1][:count]:
        groups.append(client.get_group_item(group))

    context = createContext(groups, removeNull=True)
    outputs = {"Tanium.Group(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Groups", groups)
    return human_readable, outputs, raw_response


def delete_group(client, data_args):
    id_ = data_args.get("id")
    raw_response = client.do_request("DELETE", f"groups/{id_}")
    group = {"ID": int(id_), "Deleted": True}
    human_readable = f"Group has been deleted. ID = {id_}"
    context = createContext(group, removeNull=True)
    outputs = {"Tanium.Group(val.ID && val.ID === obj.ID)": context}
    return human_readable, outputs, raw_response


def get_action_result(client, data_args):
    actions_ids = argToList(data_args.get("id"))
    action_res_outputs: List = []
    action_res_hr: List = []

    for action_id in actions_ids:
        endpoint_url = "/result_data/action/" + str(action_id)
        raw_response = client.do_request("GET", endpoint_url)
        try:
            all_devices_results = raw_response["data"]["result_sets"][0]["rows"]
            device_results = []
            for device_res in all_devices_results:
                formatted_device = {
                    "HostName": device_res["data"][0][0]["text"],
                    "Status": str(device_res["data"][1][0]["text"]).split(":")[1],
                    "ComputerID": device_res["cid"],
                }
                device_results.append(formatted_device)
            raw_response = raw_response.get("data")
            raw_response["ID"] = action_id
            action_res_outputs.append(raw_response)
            if device_results:
                action_res_hr.extend(device_results)
        except Exception:
            continue

    human_readable = tableToMarkdown(
        "Device Statuses", t=action_res_hr, removeNull=True, headers=["HostName", "Status", "ComputerID"]
    )

    context = createContext(action_res_outputs, removeNull=True)
    outputs = {"Tanium.ActionResult(val.ID && val.ID === obj.ID)": context}
    return human_readable, outputs, action_res_outputs


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    params = demisto.params()
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    domain = params.get("domain")
    # Remove trailing slash to prevent wrong URL path to service
    server = params["url"].strip("/")
    # Service base URL
    base_url = server + "/api/v2/"
    # Should we use SSL
    use_ssl = not params.get("insecure", False)
    proxy = argToBoolean(params.get("proxy", False))
    api_token = params.get("credentials_api_token", {}).get("password") or params.get("api_token")
    # [mTLS fork] The certificate can be in the credential used for the username/password or for the API token.
    client_certificate, client_certificate_passphrase = get_client_certificate_params(
        params.get("credentials"), params.get("credentials_api_token")
    )

    command = demisto.command()
    handle_proxy()
    demisto.info(f"Command being called is {command}")

    commands = {
        "test-module": test_module,
        "tn-get-system-status": get_system_status,
        "tn-get-package": get_package,
        "tn-create-package": create_package,
        "tn-list-packages": get_packages,
        "tn-get-sensor": get_sensor,
        "tn-list-sensors": get_sensors,
        "tn-ask-question": ask_question,
        "tn-get-question-metadata": get_question_metadata,
        "tn-get-question-result": get_question_result,
        "tn-create-saved-question": create_saved_question,
        "tn-get-saved-question-metadata": get_saved_question_metadata,
        "tn-get-saved-question-result": get_saved_question_result,
        "tn-list-saved-questions": get_saved_questions,
        "tn-create-action": create_action,
        "tn-create-action-by-host": create_action_by_host,
        "tn-get-action": get_action,
        "tn-list-actions": get_actions,
        "tn-create-saved-action": create_saved_action,
        "tn-get-saved-action": get_saved_action,
        "tn-list-saved-actions": get_saved_actions,
        "tn-list-saved-actions-pending-approval": get_saved_actions_pending,
        "tn-create-filter-based-group": create_filter_based_group,
        "tn-create-manual-group": create_manual_group,
        "tn-get-group": get_group,
        "tn-list-groups": get_groups,
        "tn-delete-group": delete_group,
        "tn-get-action-result": get_action_result,
    }

    try:
        # [mTLS fork] Created inside the try block, so that client certificate errors are reported like other errors.
        client = Client(
            base_url,
            username,
            password,
            domain,
            api_token=api_token,
            verify=use_ssl,
            proxy=proxy,
            client_certificate=client_certificate,
            client_certificate_passphrase=client_certificate_passphrase,
        )
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        # Log exceptions
    except Exception as e:
        err_msg = f"Error in Tanium v2 Integration [{e}]"
        return_error(err_msg, error=e)

if __name__ == "builtins":
    main()
