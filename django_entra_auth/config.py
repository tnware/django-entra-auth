import base64
import logging
import warnings
from datetime import datetime, timedelta

import requests
import requests.adapters
from urllib3.util.retry import Retry
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_der_x509_certificate
from django.conf import settings as django_settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.http import QueryDict
from django.shortcuts import render
from django.utils.module_loading import import_string

try:
    from django.urls import reverse
except ImportError:  # Django < 1.10
    from django.core.urlresolvers import reverse

logger = logging.getLogger("django_entra_auth")

AZURE_AD_SERVER = "login.microsoftonline.com"
DEFAULT_SETTINGS_CLASS = "django_entra_auth.config.Settings"


class ConfigLoadError(Exception):
    pass


def _get_settings_class():
    """
    Get the ENTRA_AUTH setting from the Django settings.
    """
    if not hasattr(django_settings, "ENTRA_AUTH"):
        msg = "The configuration directive 'ENTRA_AUTH' was not found in your Django settings"
        raise ImproperlyConfigured(msg)
    cls = django_settings.ENTRA_AUTH.get("SETTINGS_CLASS", DEFAULT_SETTINGS_CLASS)
    return import_string(cls)


class Settings(object):
    """
    Settings implementation reading from the Django settings.
    """

    def __init__(self):
        # Set defaults
        self.AUDIENCE = None  # Required
        self.BLOCK_GUEST_USERS = False
        self.BOOLEAN_CLAIM_MAPPING = {}
        self.CA_BUNDLE = True
        self.CLAIM_MAPPING = {}
        self.CLIENT_ID = None  # Required
        self.CLIENT_SECRET = None
        self.CONFIG_RELOAD_INTERVAL = 24  # hours
        self.CREATE_NEW_USERS = True
        self.DISABLE_SSO = False
        self.GROUP_TO_FLAG_MAPPING = {}
        self.GROUPS_CLAIM = "groups"
        self.LOGIN_EXEMPT_URLS = []
        self.MIRROR_GROUPS = False
        self.RELYING_PARTY_ID = None  # Required
        self.RETRIES = 3
        self.SERVER = AZURE_AD_SERVER
        self.TENANT_ID = None  # Required
        self.TIMEOUT = 5
        self.USERNAME_CLAIM = "upn"
        self.GUEST_USERNAME_CLAIM = None
        self.JWT_LEEWAY = 0
        self.CUSTOM_FAILED_RESPONSE_VIEW = (
            lambda request, error_message, status: render(
                request,
                "django_entra_auth/login_failed.html",
                {"error_message": error_message},
                status=status,
            )
        )
        self.PROXIES = None

        # Token Lifecycle Middleware settings
        self.TOKEN_REFRESH_THRESHOLD = 300  # 5 minutes
        self.STORE_OBO_TOKEN = True
        self.TOKEN_ENCRYPTION_SALT = b"django_entra_auth_token_encryption"
        self.LOGOUT_ON_TOKEN_REFRESH_FAILURE = False

        self.VERSION = "v1.0"
        self.SCOPES = []

        required_settings = [
            "AUDIENCE",
            "CLIENT_ID",
            "RELYING_PARTY_ID",
            "USERNAME_CLAIM",
            "TENANT_ID",
        ]

        deprecated_settings = {
            "AUTHORIZE_PATH": "This setting is automatically loaded from ADFS.",
            "ISSUER": "This setting is automatically loaded from ADFS.",
            "LOGIN_REDIRECT_URL": "Instead use the standard Django settings with the same name.",
            "REDIR_URI": "This setting is automatically determined based on the URL configuration of Django.",
            "SIGNING_CERT": "The token signing certificates are automatically loaded from ADFS.",
            "TOKEN_PATH": "This setting is automatically loaded from ADFS.",
        }

        if not hasattr(django_settings, "ENTRA_AUTH"):
            msg = "The configuration directive 'ENTRA_AUTH' was not found in your Django settings"
            raise ImproperlyConfigured(msg)
        _settings = django_settings.ENTRA_AUTH
        # Settings class is loaded by now. Delete this setting
        if "SETTINGS_CLASS" in _settings:
            del _settings["SETTINGS_CLASS"]

        # Handle deprecated settings
        for setting, message in deprecated_settings.items():
            if setting in _settings:
                warnings.warn(
                    "Setting {} is deprecated and it's value was ignored. {}".format(
                        setting, message
                    ),
                    DeprecationWarning,
                )
                del _settings[setting]

        if "CERT_MAX_AGE" in _settings:
            _settings["CONFIG_RELOAD_INTERVAL"] = _settings["CERT_MAX_AGE"]
            warnings.warn(
                "Setting CERT_MAX_AGE has been renamed to CONFIG_RELOAD_INTERVAL. The value was copied.",
                DeprecationWarning,
            )
            del _settings["CERT_MAX_AGE"]

        if "GROUP_CLAIM" in _settings:
            _settings["GROUPS_CLAIM"] = _settings["GROUP_CLAIM"]
            warnings.warn(
                "Setting GROUP_CLAIM has been renamed to GROUPS_CLAIM. The value was copied.",
                DeprecationWarning,
            )
            del _settings["GROUP_CLAIM"]

        if "RESOURCE" in _settings:
            _settings["RELYING_PARTY_ID"] = _settings["RESOURCE"]
            del _settings["RESOURCE"]

        if "SERVER" in _settings:
            warnings.warn(
                "Setting SERVER is not required and will be ignored. Entra ID server will be used.",
                DeprecationWarning,
            )
            del _settings["SERVER"]

        if self.VERSION == "v2.0" and not self.SCOPES and self.RELYING_PARTY_ID:
            warnings.warn(
                "Use `SCOPES` for AzureAD instead of RELYING_PARTY_ID",
                DeprecationWarning,
            )
        if not isinstance(self.SCOPES, list):
            raise ImproperlyConfigured("Scopes must be a list")

        # Overwrite defaults with user settings
        for setting, value in _settings.items():
            if hasattr(self, setting):
                setattr(self, setting, value)
            else:
                msg = "'{0}' is not a valid configuration directive for django_entra_auth."
                raise ImproperlyConfigured(msg.format(setting))

        for setting in required_settings:
            if not getattr(self, setting):
                msg = "django_entra_auth setting '{0}' has not been set".format(setting)
                raise ImproperlyConfigured(msg)

        # Setup dynamic settings
        if not callable(self.CUSTOM_FAILED_RESPONSE_VIEW):
            self.CUSTOM_FAILED_RESPONSE_VIEW = import_string(
                self.CUSTOM_FAILED_RESPONSE_VIEW
            )

        # Validate setting conflicts
        usermodel = get_user_model()
        if usermodel.USERNAME_FIELD in self.CLAIM_MAPPING:
            raise ImproperlyConfigured(
                "You cannot set the username field of the user model from "
                "the CLAIM_MAPPING setting. Instead use the USERNAME_CLAIM setting."
            )


class ProviderConfig(object):
    def __init__(self):
        self._config_timestamp = None
        self._mode = None

        self.authorization_endpoint = None
        self.signing_keys = None
        self.token_endpoint = None
        self.end_session_endpoint = None
        self.issuer = None
        self.msgraph_endpoint = None

        allowed_methods = frozenset(
            ["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )

        retry = Retry(
            total=settings.RETRIES,
            read=settings.RETRIES,
            connect=settings.RETRIES,
            backoff_factor=0.3,
            allowed_methods=allowed_methods,
        )
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.verify = settings.CA_BUNDLE
        if hasattr(settings, "PROXIES"):
            self.session.proxies = settings.PROXIES

    def load_config(self):
        # If loaded data is too old, reload it again
        refresh_time = datetime.now() - timedelta(hours=settings.CONFIG_RELOAD_INTERVAL)
        if self._config_timestamp is None or self._config_timestamp < refresh_time:
            logger.debug("Loading ID Provider configuration.")
            try:
                loaded = self._load_openid_config()
                self._mode = "openid_connect"
                logger.info("Loaded: %s", loaded)
            except ConfigLoadError:
                if self._config_timestamp is None:
                    msg = (
                        "Could not load OpenID Connect configuration from Entra ID server. "
                        "Authentication will not be possible. "
                        "Verify your settings and the connection with the Entra ID server."
                    )
                    logger.critical(msg)
                    raise RuntimeError(msg)
                else:
                    # We got data from the previous time. Log a message, but don't abort.
                    logger.warning(
                        "Could not load OpenID Connect configuration from Entra ID server. Keeping previous configurations"
                    )
            self._config_timestamp = datetime.now()

            logger.info("Loaded settings from Entra ID server.")
            logger.info("authorization endpoint: %s", self.authorization_endpoint)
            logger.info("token endpoint:         %s", self.token_endpoint)
            logger.info("end session endpoint:   %s", self.end_session_endpoint)
            logger.info("issuer:                 %s", self.issuer)
            logger.info("msgraph endpoint:       %s", self.msgraph_endpoint)

    def _load_openid_config(self):
        if settings.VERSION != "v1.0":
            config_url = (
                "https://{}/{}/{}/.well-known/openid-configuration?appid={}".format(
                    settings.SERVER,
                    settings.TENANT_ID,
                    settings.VERSION,
                    settings.CLIENT_ID,
                )
            )
        else:
            config_url = (
                "https://{}/{}/.well-known/openid-configuration?appid={}".format(
                    settings.SERVER, settings.TENANT_ID, settings.CLIENT_ID
                )
            )

        try:
            logger.info("Trying to get OpenID Connect config from %s", config_url)
            response = self.session.get(config_url, timeout=settings.TIMEOUT)
            response.raise_for_status()
            openid_cfg = response.json()

            response = self.session.get(
                openid_cfg["jwks_uri"], timeout=settings.TIMEOUT
            )
            response.raise_for_status()
            signing_certificates = [
                x["x5c"][0]
                for x in response.json()["keys"]
                if x.get("use", "sig") == "sig"
            ]
            #                               ^^^
            # https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.7
            # The PKIX certificate containing the key value MUST be the first certificate
        except requests.HTTPError:
            raise ConfigLoadError

        self._load_keys(signing_certificates)
        try:
            self.authorization_endpoint = openid_cfg["authorization_endpoint"]
            self.token_endpoint = openid_cfg["token_endpoint"]
            self.end_session_endpoint = openid_cfg["end_session_endpoint"]
            self.issuer = openid_cfg["issuer"]
            self.msgraph_endpoint = openid_cfg.get(
                "msgraph_host", "graph.microsoft.com"
            )
        except KeyError:
            raise ConfigLoadError
        return True

    def _load_keys(self, certificates):
        new_keys = []
        for cert in certificates:
            logger.debug("Loading public key from certificate: %s", cert)
            cert_obj = load_der_x509_certificate(base64.b64decode(cert), backend)
            new_keys.append(cert_obj.public_key())
        self.signing_keys = new_keys

    def redirect_uri(self, request):
        self.load_config()
        return request.build_absolute_uri(reverse("django_entra_auth:callback"))

    def build_authorization_endpoint(self, request, disable_sso=None, force_mfa=False):
        """
        This function returns the Entra ID authorization URL.

        Args:
            request(django.http.request.HttpRequest): A django Request object
            disable_sso(bool): Whether to disable single sign-on and force the Entra ID server to show a login prompt.
            force_mfa(bool): If MFA should be forced

        Returns:
            str: The redirect URI

        """
        self.load_config()
        if request.method == "POST":
            redirect_to = request.POST.get(REDIRECT_FIELD_NAME, None)
        else:
            redirect_to = request.GET.get(REDIRECT_FIELD_NAME, None)
        if not redirect_to:
            redirect_to = django_settings.LOGIN_REDIRECT_URL
        redirect_to = base64.urlsafe_b64encode(redirect_to.encode()).decode()
        query = QueryDict(mutable=True)
        query.update(
            {
                "response_type": "code",
                "client_id": settings.CLIENT_ID,
                "redirect_uri": self.redirect_uri(request),
                "state": redirect_to,
            }
        )

        if settings.VERSION == "v2.0":
            if settings.SCOPES:
                query["scope"] = " ".join(settings.SCOPES)
            else:
                query["scope"] = f"openid api://{settings.RELYING_PARTY_ID}/.default"
        else:
            query["scope"] = "openid"
            query["resource"] = settings.RELYING_PARTY_ID

        if (disable_sso is None and settings.DISABLE_SSO) or disable_sso is True:
            query["prompt"] = "login"
        if force_mfa:
            query["amr_values"] = "ngcmfa"

        return "{0}?{1}".format(self.authorization_endpoint, query.urlencode())

    def build_end_session_endpoint(self):
        """
        This function returns the ADFS end session URL to log a user out.

        Returns:
            str: The redirect URI

        """
        self.load_config()
        return self.end_session_endpoint


settings_cls = _get_settings_class()
settings = settings_cls()
provider_config = ProviderConfig()
