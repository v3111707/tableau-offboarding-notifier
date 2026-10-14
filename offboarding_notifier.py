#!/usr/bin/env python3

import base64
import json
import logging
import os
import re
import smtplib
import ssl
import sys
import tomllib
import copy
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from typing import Any, Literal, Optional, TypedDict
from urllib.parse import urljoin

import hvac
import lxml.etree as etree
import requests
import sentry_sdk
import tableauserverclient as TSC
import typer
from jinja2 import Environment, FileSystemLoader
from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber
from signxml import methods
from signxml.signer import XMLSigner
from zabbix_utils import Sender as ZabbixSender

SCRIPT_NAME = os.path.basename(__file__)

CONF_NAME = "config.toml"
SCRIPT_HOME = os.path.dirname(os.path.realpath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_HOME, CONF_NAME)
LOGFILE_PATH = os.path.join(SCRIPT_HOME, SCRIPT_NAME.split(".")[0] + ".log")

ZAB_KEY_EXITCODE = "hrms_report_sender_exit_code"
ZAB_KEY_HEARTBEAT = "hrms_report_sender_heartbeat"
MAIL_TEMPLATE = "leaving_users_report.html.jinja2"
SENTRY_DENYLIST = DEFAULT_DENYLIST + [
    "vault_resp",
    "creds",
    "common_creds",
    "conf",
    "mail_creds",
    "tableau_creds",
]

NSMAP = {
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

BUSINESS_OWNER_RE = re.compile(
    r"business\s+owner\s*[-–—:]\s*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", re.IGNORECASE
)


def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def convert_date(date_raw: str) -> datetime:
    if not isinstance(date_raw, str):
        raise ValueError(
            f"Invalid HRMS date type: expected str, got {type(date_raw).__name__}: {date_raw!r}"
        )

    match = re.search(r"\((\d+)\D", date_raw)
    if not match:
        raise ValueError(f"Unsupported HRMS date format: {date_raw!r}")

    timestamp_ms = int(match.group(1))
    return datetime.fromtimestamp(timestamp_ms / 1000)


def init_logger(
    debug: bool = False,
    log_name: str = "main",
    path: str = "None",
    max_bytes: int = 20971520,
    backup_count: int = 5,
):
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)

    logger.handlers.clear()

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(asctime)s - %(name)s: %(message)s"))
    sh.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(sh)

    if path:
        fh = RotatingFileHandler(
            filename=path, maxBytes=max_bytes, backupCount=backup_count
        )
        fh.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        fh.setLevel(logging.DEBUG if debug else logging.INFO)
        logger.addHandler(fh)

    logger.debug("Set level DEBUG")


def build_assertion(
    client_id: str,
    user_id: str,
    token_url: str,
    expire_minutes: int = 10,
    use_username: bool = False,
):
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=10)
    not_on_or_after = now + timedelta(minutes=expire_minutes)
    assertion_id = "_" + str(uuid.uuid4())
    session_index = "_" + str(uuid.uuid4())

    assertion = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
        nsmap=NSMAP,
        ID=assertion_id,
        Version="2.0",
        IssueInstant=iso_z(now),
    )

    issuer = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
    )
    issuer.text = "www.successfactors.com"

    subject = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
    )
    name_id = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}NameID",
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )
    name_id.text = user_id

    subj_conf = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    etree.SubElement(
        subj_conf,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
        Recipient=token_url,
        NotOnOrAfter=iso_z(not_on_or_after),
    )

    conditions = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
        NotBefore=iso_z(not_before),
        NotOnOrAfter=iso_z(not_on_or_after),
    )
    aud_restr = etree.SubElement(
        conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
    )
    audience = etree.SubElement(
        aud_restr, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    )
    audience.text = "www.successfactors.com"

    authn_stmt = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
        AuthnInstant=iso_z(now),
        SessionIndex=session_index,
    )
    authn_ctx = etree.SubElement(
        authn_stmt, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
    )
    authn_ctx_ref = etree.SubElement(
        authn_ctx, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
    )
    authn_ctx_ref.text = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    def add_attr(name: str, value: str):
        stmt = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
        )
        attr = etree.SubElement(
            stmt, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute", Name=name
        )
        val = etree.SubElement(
            attr,
            "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue",
            attrib={"{http://www.w3.org/2001/XMLSchema-instance}type": "xs:string"},
            nsmap={
                "xs": "http://www.w3.org/2001/XMLSchema",
                "xsi": "http://www.w3.org/2001/XMLSchema-instance",
            },
        )
        val.text = value

    add_attr("api_key", client_id)
    if use_username:
        add_attr("use_username", "true")

    return assertion, assertion_id


def sign_assertion(assertion, assertion_id: str, cert_pem: str, key_pem: str):
    # cert_pem = open(cert_pem_path, "rb").read()
    # key_pem = open(key_pem_path, "rb").read()

    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(
        assertion,
        key=key_pem,
        cert=cert_pem,
        reference_uri=assertion_id,
        id_attribute="ID",
    )
    return signed


class ZabSender:
    def __init__(
        self,
        config_file: str = "/etc/zabbix/zabbix_agentd.conf",
        stub: bool = False,
    ):
        self._stub = stub
        if not self._stub:
            self.logger = logging.getLogger("main.Zabbix_sender")
            zabbix_config = open(config_file).read()
            match = re.search(r"ServerActive=(.+)", zabbix_config)
            if match is None:
                raise ValueError("ServerActive not found in zabbix config")
            self._server = match.group(1)

            self.logger.debug(f"self.server: {self._server}")
            match = re.search(r"Hostname=(.+)", zabbix_config)
            if match is None:
                raise ValueError("Hostname not found in zabbix config")
            self._hostname = match.group(1)
            self._sender = ZabbixSender(server=self._server)
            self.logger.debug(f"self.hostname: {self._hostname}")

    def send(self, key: str, value: str):
        if not self._stub:
            self.logger.info(f"Send {key}={value}  to {self._server}")
            resp = self._sender.send_value(
                host=self._hostname,
                key=key,
                value=value,
            )
            return resp


class MailStatus:
    _first_mail = "first_mail"
    _second_mail = "second_mail"
    _third_mail = "third_mail"
    _logger_name = "main.MailStatus"

    def __init__(self, path: str):
        self.logger = logging.getLogger(self._logger_name)
        self._path = path
        self._data = {}
        if os.path.isfile(path):
            self.logger.info(f"Loading {path}")
            with open(self._path, "r") as f:
                self._data = json.load(f)

    def _save_data(self):
        with open(self._path, "w") as f:
            json.dump(self._data, f)

    def get_first_mail_state(self, username: str):
        if self._data.get(username) and self._data.get(username, {}).get(
            self._first_mail
        ):
            return True
        return False

    def get_second_mail_state(self, username: str):
        if self._data.get(username) and self._data.get(username, {}).get(
            self._second_mail
        ):
            return True
        return False

    def get_third_mail_state(self, username: str):
        if self._data.get(username) and self._data.get(username, {}).get(
            self._third_mail
        ):
            return True
        return False

    def set_first_mail_state(self, username: str):
        self.logger.info(f"Set first mail to True for {username}")
        self._data[username] = {
            **self._data.get(username, {}),
            **{self._first_mail: True},
        }
        self._save_data()

    def set_second_mail_state(self, username: str):
        self.logger.info(f"Set second mail to True for {username}")
        self._data[username] = {
            **self._data.get(username, {}),
            **{self._second_mail: True},
        }
        self._save_data()

    def set_third_mail_state(self, username: str):
        self.logger.info(f"Set third mail to True for {username}")
        self._data[username] = {
            **self._data.get(username, {}),
            **{self._third_mail: True},
        }
        self._save_data()

    def clean(self, username: str):
        if username in self._data:
            self.logger.info(f"Clean mail status for {username}")
            self._data.pop(username)
            self._save_data()


class EmailSender:
    _logger_name = "main.EmailSender"

    def __init__(
        self,
        host: str = "",
        username: str = "",
        password: str = "",
        port: int = 25,
        sender: str = "",
    ):
        self.logger = logging.getLogger(self._logger_name)
        if not sender:
            sender = username
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.sender = sender
        self.context = ssl.create_default_context()

    def send_mail(
        self, to: list, subject: str, msg_plain: str = "", msg_html: str = ""
    ):
        message = MIMEMultipart("mixed")
        message["to"] = ", ".join(to)
        message["from"] = self.sender
        message["subject"] = subject

        message_alternative = MIMEMultipart("alternative")
        message_related = MIMEMultipart("related")
        if msg_html:
            message_related.attach(MIMEText(msg_html, "html"))
        if msg_plain:
            message_alternative.attach(MIMEText(msg_plain, "plain"))
        message_alternative.attach(message_related)
        message.attach(message_alternative)

        self.logger.debug(f"message: {message}")
        with smtplib.SMTP(host=self.host, port=self.port) as server:
            server.ehlo()
            server.starttls(context=self.context)

            if self.username and self.password:
                server.login(user=self.username, password=self.password)

            self.logger.info(f'Sending mail from "{self.sender}" to; "{to}" ')
            sendmail_resp = server.sendmail(
                from_addr=self.sender, to_addrs=to, msg=message.as_string()
            )
            self.logger.debug(f"sendmail_resp: {sendmail_resp}")
        return sendmail_resp

    def load_template(self, template: str):
        dirname = os.path.dirname
        templates_dir = dirname(os.path.realpath(__file__))
        env = Environment(loader=FileSystemLoader(templates_dir))
        return env.get_template(template)

    def _render_data(self, data: dict, template_name: str):
        template = self.load_template(template_name)
        rendered = template.render(**data)
        return rendered

    def send_templated_mail(
        self, to: list, subject: str, template_name: str, data: dict
    ):
        body = self._render_data(data=data, template_name=template_name)
        return self.send_mail(to=to, subject=subject, msg_html=body)

    def __enter__(self):
        return self

    def __exit__(self, exc, val, tb):
        pass


ResourceRole = Literal["owner", "business_owner"]


class SFEmpJob(TypedDict):
    userId: str
    managerId: str
    customDate4: str  # OData date, e.g. "/Date(1793404800000)/"


class SFUser(TypedDict):
    userId: str
    displayName: str
    email: str
    username: str


class TableauWorkbook(TypedDict):
    name: str
    project_name: str
    roles: list[ResourceRole]


class TableauProject(TypedDict):
    name: str
    path: str
    roles: list[ResourceRole]


class TableauSiteResources(TypedDict):
    user_content_url: str
    workbooks: list[TableauWorkbook]
    projects: list[TableauProject]


class ReportItem(SFUser):
    manager: SFUser
    termination_date: datetime
    tableau_url: str
    tableau_resources: dict[str, TableauSiteResources]  # key: site name


class LeavingUserReport(SFUser):
    manager: SFUser
    termination_date: datetime
    tableau_resources: dict[str, TableauSiteResources]  # key: site name


class SuccessFactorsClient:
    logger_name: str = "main.SFC"
    _timeout: tuple[int, int] = (5, 30)  # (connect_timeout, read_timeout)

    def __init__(self, url: str) -> None:
        self.log: logging.Logger = logging.getLogger(self.logger_name)
        self.base_url: str = url
        self.base_headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
        self.token: dict[str, Any] = {}
        self.log.debug("End init")

    def auth(
        self,
        company_id: str,
        client_id: str,
        assertion: str,
        grant_type: str = "urn:ietf:params:oauth:grant-type:saml2-bearer",
    ) -> None:
        resource_path = "oauth/token"
        url = urljoin(self.base_url, resource_path)
        headers = self.base_headers

        params = {
            "company_id": company_id,
            "client_id": client_id,
            "grant_type": grant_type,
            "assertion": assertion,
            "new_token": True,
        }

        resp = requests.post(
            url=url,
            params=params,
            headers=headers,
            timeout=self._timeout,
        )
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exp:
            if resp.status_code == 401:
                logging.error(resp.json())
            raise exp
        self.token = resp.json()

    def get_leaving_users(self, up_to: datetime) -> list[SFEmpJob]:
        resource_path = "odata/v2/EmpJob"
        url = urljoin(self.base_url, resource_path)
        token_type = self.token["token_type"]
        access_token = self.token["access_token"]
        from_date = str(datetime.now() + timedelta(days=-7))

        params = {
            "format": "json",
            "$select": "userId,managerId,customDate4",
            "toDate": str(up_to.date()),
            "$filter": f"customDate4 ge '{from_date}' "
            f"and userNav/status in 't','f','T','F','e','d'",
        }

        headers = {
            "Authorization": f"{token_type} {access_token}",
            "accept": "application/json",
        }

        resp = requests.get(
            url=url,
            headers=headers,
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        users = body["d"]["results"]
        for user in users:
            user.pop("__metadata", None)
        return users

    def get_user_by_id(self, user_id: str) -> SFUser:
        resource_path = f"odata/v2/User('{user_id}')"
        url = urljoin(self.base_url, resource_path)

        token_type = self.token["token_type"]
        access_token = self.token["access_token"]
        headers = {
            "Authorization": f"{token_type} {access_token}",
            "accept": "application/json",
        }

        params = {"format": "json", "$select": "userId,displayName,email,username"}
        self.log.debug(f"requests.get: {url}")
        resp = requests.get(
            url=url,
            headers=headers,
            params=params,
            timeout=self._timeout,
        )
        try:
            resp.raise_for_status()
        except Exception as e:
            self.log.warning(f"Error while get f{url} ")
            self.log.warning(resp.text)
            self.log.exception(e)
            raise e
        body = resp.json()["d"]
        body.pop("__metadata")
        return body


def _load_conf_and_vault(config_path: str) -> tuple[dict, dict, dict]:
    with open(config_path, "rb") as f:
        conf = tomllib.load(f)

    vault_client = hvac.Client(url=conf["vault"]["url"])
    vault_client.auth.approle.login(
        role_id=conf["vault"]["role_id"],
        secret_id=conf["vault"]["secret_id"],
    )

    creds = vault_client.secrets.kv.v1.read_secret(conf["vault"]["paths"]["creds"])[
        "data"
    ]
    mail_creds = vault_client.secrets.kv.v1.read_secret(
        conf["vault"]["paths"]["common"] + "mail-bot"
    )["data"]

    params = vault_client.secrets.kv.v1.read_secret(conf["vault"]["paths"]["params"])[
        "data"
    ]
    return params, creds, mail_creds


def get_business_owner_email(
    resource: TSC.WorkbookItem | TSC.ProjectItem,
) -> str | None:
    """Return business owner's email from the resource description, if any."""
    match = BUSINESS_OWNER_RE.search(resource.description or "")
    return match.group(1).lower() if match else None


def resource_roles(
    resource: TSC.WorkbookItem | TSC.ProjectItem,
    users_by_id: dict[str, TSC.UserItem],
    users_by_email: dict[str, TSC.UserItem],
) -> list[tuple[str, ResourceRole]]:
    roles: list[tuple[str, ResourceRole]] = []
    owner = users_by_id.get(resource.owner_id)
    if owner:
        roles.append((owner.name.lower(), "owner"))
    business_owner = users_by_email.get(get_business_owner_email(resource) or "")
    if business_owner:
        roles.append((business_owner.name.lower(), "business_owner"))
    return roles


app = typer.Typer(add_completion=False, pretty_exceptions_enable=False)


@app.command(context_settings=dict(help_option_names=["-h", "--help"]))
def cli(
    debug: bool = typer.Option(False, "-d", "--debug", is_flag=True, show_default=True),
    mail_to: Optional[str] = typer.Option(None, "-m", "--mail_to", show_default=False),
    print_data: Optional[bool] = typer.Option(
        False,
        "-p",
        is_flag=True,
        show_default=True,
        help="Print data from HRMS and exit",
    ),
    zab_test: Optional[bool] = typer.Option(
        False, "--zt", is_flag=True, show_default=True, help='Send to zabbix "1"'
    ),
    load_file: Optional[str] = typer.Option(None, "-l", show_default=True),
    safe_file: Optional[str] = typer.Option(None, "-s", show_default=True),
    zabbix_stub: bool = typer.Option(
        False,
        "--zs",
        is_flag=True,
        show_default=True,
        help="Using a stub instead Zabbix send",
    ),
):
    init_logger(debug=debug, path=LOGFILE_PATH)
    log = logging.getLogger("main")

    exit_code = 0
    params, creds, mail_creds = _load_conf_and_vault(CONFIG_PATH)

    mail_states = MailStatus("hrms_report_sender_email_states.json")

    tableau_url = creds["ts_url"]

    sentry_sdk.init(
        dsn=params["sentry_dsn"],
        event_scrubber=EventScrubber(denylist=SENTRY_DENYLIST),
    )

    sentry_sdk.set_tags(
        {
            # 'severity': "high",
            "script": SCRIPT_NAME,
            # "jira": True,
        }
    )

    zab_sender = ZabSender(stub=zabbix_stub)
    zab_sender.send(key=ZAB_KEY_HEARTBEAT, value="1")

    if zab_test:
        zab_sender.send(key=ZAB_KEY_EXITCODE, value="1")
        raise typer.Exit()

    report_data: list[ReportItem]
    if load_file:
        log.info(f'Opening "{os.path.abspath(load_file)}"')
        with open(os.path.abspath(load_file), "r") as f:
            report_data = json.load(f)
        for i in report_data:
            i["termination_date"] = datetime.strptime(
                i["termination_date"], "%Y-%m-%d %H:%M:%S"
            )

    else:
        assertion, assertion_id = build_assertion(
            client_id=creds["hrms_client_id"],
            user_id=creds["hrms_user_id"],
            token_url=creds["hrms_token_url"],
        )
        assertion_signed = sign_assertion(
            assertion=assertion,
            assertion_id=assertion_id,
            cert_pem=creds["hrms_cert_pem"],
            key_pem=creds["hrms_key_pem"],
        )
        xml_bytes = etree.tostring(
            assertion_signed, encoding="utf-8", xml_declaration=False
        )
        b64_assertion = base64.b64encode(xml_bytes).decode("ascii")

        sfc = SuccessFactorsClient(url=creds["hrms_url"])
        sfc.auth(
            company_id=creds["hrms_company_id"],
            client_id=creds["hrms_client_id"],
            assertion=b64_assertion,
        )
        users = sfc.get_leaving_users(up_to=datetime.now() + timedelta(days=30))
        log.debug(f"get_leaving_users resp:\n {users}")
        report_data = []
        log.info("Leaving users in hrms:")
        for u in users:
            user_id = u["userId"]
            manager_id = u["managerId"]
            termination_date = convert_date(u["customDate4"])
            log.info(f"Get user date: {user_id=}")
            user = sfc.get_user_by_id(user_id)
            log.info(f"Get manager date: {manager_id=}")
            manager_data = sfc.get_user_by_id(manager_id)
            username = user["username"]

            report_data.append(
                {
                    **user,
                    "manager": manager_data,
                    "termination_date": termination_date,
                    "tableau_url": tableau_url,
                    "tableau_resources": {},
                }
            )
            log.info(
                f"User:{username},  termination date:{termination_date.date()}, manager's email: {manager_data['email']}"
            )
    if print_data:
        print(json.dumps(report_data, indent=2, default=str))
        raise typer.Exit()

    if safe_file:
        log.info(f'Saving to "{os.path.abspath(safe_file)}"')
        dumped = json.dumps(
            report_data,
            default=lambda o: o.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(o, datetime)
            else str(o),
        )
        with open(os.path.abspath(safe_file), "w") as f:
            f.write(dumped)
        raise typer.Exit()

    tableau_auth = TSC.TableauAuth(
        username=creds["ts_username"],
        password=creds["ts_password"],
    )
    log.debug(f"Log into {tableau_url}")
    server = TSC.Server(
        server_address=tableau_url,
        use_server_version=True,
    )

    leaving_users = copy.deepcopy(report_data)
    for item in leaving_users:
        item.pop("tableau_url", None)
        item.pop("tableau_resources", None)

    leaving_users_report: list[LeavingUserReport] = [
        {**u, "tableau_resources": {}} for u in leaving_users
    ]

    with server.auth.sign_in(tableau_auth):
        for site in TSC.Pager(server.sites):
            server.auth.switch_site(site)
            log.debug(f"Processing site: {site.name} ({server.site_id})")
            all_projects = list(TSC.Pager(server.projects))
            all_workbooks = list(TSC.Pager(server.workbooks))
            all_users = list(TSC.Pager(server.users))
            users_by_id = {i.id: i for i in all_users}
            users_by_email = {i.email.lower(): i for i in all_users if i.email}
            projects_by_id = {i.id: i for i in all_projects}
            project_id_path = {}
            for _, project in projects_by_id.items():
                path = []
                parent_id = project.parent_id
                while True:
                    if parent_id:
                        path.append(projects_by_id[parent_id].name)
                        parent_id = projects_by_id[parent_id].parent_id
                    else:
                        break
                path.append("Home")
                path.reverse()
                project_id_path[project.id] = " / ".join(path)

            workbooks_by_user: dict[str, dict[str, TableauWorkbook]] = defaultdict(dict)
            projects_by_user: dict[str, dict[str, TableauProject]] = defaultdict(dict)

            for wb in all_workbooks:
                for username, role in resource_roles(wb, users_by_id, users_by_email):
                    log.debug(f"[{site.name}] workbook '{wb.project_name} / {wb.name}': {username} is {role}")
                    wb_item = workbooks_by_user[username].setdefault(
                        wb.id,
                        {"name": wb.name, "project_name": wb.project_name, "roles": []},
                    )
                    if role not in wb_item["roles"]:
                        wb_item["roles"].append(role)

            for pr in all_projects:
                for username, role in resource_roles(pr, users_by_id, users_by_email):
                    log.debug(f"[{site.name}] project '{project_id_path[pr.id]} / {pr.name}': {username} is {role}")
                    pr_item = projects_by_user[username].setdefault(
                        pr.id,
                        {"name": pr.name, "path": project_id_path[pr.id], "roles": []},
                    )
                    if role not in pr_item["roles"]:
                        pr_item["roles"].append(role)

            for user_data in leaving_users_report:
                username = user_data["username"].lower()
                workbooks = list(workbooks_by_user.get(username, {}).values())
                projects = list(projects_by_user.get(username, {}).values())
                if not (workbooks or projects):
                    continue
                if site.content_url:
                    user_content_url = f"{server.server_address}#/site/{site.content_url}/user/local/{user_data['username']}/content"
                else:
                    user_content_url = f"{server.server_address}#/user/local/{user_data['username']}/content"
                user_data["tableau_resources"][site.name] = {
                    "user_content_url": user_content_url,
                    "workbooks": workbooks,
                    "projects": projects,
                }

    with EmailSender(**mail_creds) as mail_sender:
        for i in leaving_users_report:
            if not i["tableau_resources"]:
                log.info(f"{i['username']} doesn't have any resources. Ignore")

        leaving_users_report = [i for i in leaving_users_report if i["tableau_resources"]]
        for user_data in leaving_users_report:
            days_left = (user_data["termination_date"] - datetime.now()).days
            username = user_data["username"]
            log.info(f"Processing {user_data['username']}, days_left: {days_left}")
            if mail_to:
                recipients = mail_to.split(",")
            else:
                recipients = list(
                    set(
                        [i.strip() for i in params["mail_to"].split(",")]
                        + [user_data["email"], user_data["manager"]["email"]]
                    )
                )
            subject = f"Moving {tableau_url.replace('https://', '')} reports of the user leaving the company"

            if days_left < -5:
                log.info("days_left less than -5; Clean")
                mail_states.clean(username)
            elif not user_data.get("tableau_resources"):
                log.info("tableau_resources is None. Ignore")
            elif days_left < 0 and not mail_states.get_third_mail_state(username):
                log.info(f"Send third mail to {recipients}")
                resp = mail_sender.send_templated_mail(
                    to=recipients,
                    subject=subject,
                    template_name=MAIL_TEMPLATE,
                    data=user_data,
                )
                log.info(f"send_templated_mail resp: {resp}")
                mail_states.set_third_mail_state(username)
            elif days_left < 7 and not mail_states.get_second_mail_state(username):
                log.info(f"Send second mail to {recipients}")
                resp = mail_sender.send_templated_mail(
                    to=recipients,
                    subject=subject,
                    template_name=MAIL_TEMPLATE,
                    data=user_data,
                )
                log.info(f"send_templated_mail resp: {resp}")
                mail_states.set_second_mail_state(username)
            elif days_left >= 7 and not mail_states.get_first_mail_state(username):
                log.info(f"Send first mail to {recipients}")
                resp = mail_sender.send_templated_mail(
                    to=recipients,
                    subject=subject,
                    template_name=MAIL_TEMPLATE,
                    data=user_data,
                )
                log.debug(f"send_templated_mail resp: {resp}")
                mail_states.set_first_mail_state(username)

    log.info(f'Send to zabbix "{exit_code}"')
    zab_sender.send(key=ZAB_KEY_EXITCODE, value=str(exit_code))


if __name__ == "__main__":
    app()
