

try:
    from urllib.parse import parse_qs, urlparse
except ImportError:  # Python 2.7
    from urlparse import urlparse, parse_qs

from copy import deepcopy

from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase
from mock import Mock, patch

from django_entra_auth import signals
from django_entra_auth.backend import AdfsAuthCodeBackend
from django_entra_auth.config import ProviderConfig, Settings

from .utils import mock_adfs


class AuthenticationTests(TestCase):
    def setUp(self):
        Group.objects.create(name="group1")
        Group.objects.create(name="group2")
        Group.objects.create(name="group3")
        self.request = RequestFactory().get("/oauth2/callback")
        self.signal_handler = Mock()
        signals.post_authenticate.connect(self.signal_handler)

    @mock_adfs("azure")
    def test_with_auth_code_azure(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_entra_auth.config.django_settings", settings):
            with patch("django_entra_auth.config.settings", Settings()):
                with patch(
                    "django_entra_auth.backend.provider_config", ProviderConfig()
                ):
                    backend = AdfsAuthCodeBackend()
                    user = backend.authenticate(
                        self.request, authorization_code="dummycode"
                    )
                    self.assertIsInstance(user, User)
                    self.assertEqual(user.first_name, "John")
                    self.assertEqual(user.last_name, "Doe")
                    self.assertEqual(user.email, "john.doe@example.com")
                    self.assertEqual(len(user.groups.all()), 2)
                    self.assertEqual(user.groups.all()[0].name, "group1")
                    self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("azure", guest=True)
    def test_with_auth_code_azure_guest_block(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        settings.ENTRA_AUTH["BLOCK_GUEST_USERS"] = True
        # Patch audience since we're patching django_entra_auth.backend.settings to load Settings() as well
        settings.ENTRA_AUTH["AUDIENCE"] = (
            "microsoft:identityserver:your-RelyingPartyTrust-identifier"
        )
        with patch("django_entra_auth.config.django_settings", settings):
            with patch("django_entra_auth.backend.settings", Settings()):
                with patch("django_entra_auth.config.settings", Settings()):
                    with patch(
                        "django_entra_auth.backend.provider_config", ProviderConfig()
                    ):
                        with self.assertRaises(PermissionDenied, msg=""):
                            backend = AdfsAuthCodeBackend()
                            _ = backend.authenticate(
                                self.request, authorization_code="dummycode"
                            )

    @mock_adfs("azure", guest=True)
    def test_with_auth_code_azure_guest_no_block(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        settings.ENTRA_AUTH["BLOCK_GUEST_USERS"] = False
        # Patch audience since we're patching django_entra_auth.backend.settings to load Settings() as well
        settings.ENTRA_AUTH["AUDIENCE"] = (
            "microsoft:identityserver:your-RelyingPartyTrust-identifier"
        )
        with patch("django_entra_auth.config.django_settings", settings):
            with patch("django_entra_auth.backend.settings", Settings()):
                with patch("django_entra_auth.config.settings", Settings()):
                    with patch(
                        "django_entra_auth.backend.provider_config", ProviderConfig()
                    ):
                        backend = AdfsAuthCodeBackend()
                        user = backend.authenticate(
                            self.request, authorization_code="dummycode"
                        )
                        self.assertIsInstance(user, User)
                        self.assertEqual(user.first_name, "John")
                        self.assertEqual(user.last_name, "Doe")
                        self.assertEqual(user.email, "john.doe@example.com")
                        self.assertEqual(len(user.groups.all()), 2)
                        self.assertEqual(user.groups.all()[0].name, "group1")
                        self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("azure", version="v2.0")
    def test_version_two_endpoint_calls_correct_url(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        settings.ENTRA_AUTH["VERSION"] = "v2.0"
        # Patch audience since we're patching django_entra_auth.backend.settings to load Settings() as well
        with patch("django_entra_auth.config.django_settings", settings):
            with patch("django_entra_auth.backend.settings", Settings()):
                with patch("django_entra_auth.config.settings", Settings()):
                    with patch(
                        "django_entra_auth.backend.provider_config", ProviderConfig()
                    ):
                        backend = AdfsAuthCodeBackend()
                        user = backend.authenticate(
                            self.request, authorization_code="dummycode"
                        )
                        self.assertIsInstance(user, User)
                        self.assertEqual(user.first_name, "John")
                        self.assertEqual(user.last_name, "Doe")
                        self.assertEqual(user.email, "john.doe@example.com")
                        self.assertEqual(len(user.groups.all()), 2)
                        self.assertEqual(user.groups.all()[0].name, "group1")
                        self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("azure")
    def test_oauth_redir_azure_version_one(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        with (
            patch("django_entra_auth.config.django_settings", settings),
            patch("django_entra_auth.config.settings", Settings()),
            patch("django_entra_auth.views.provider_config", ProviderConfig()),
        ):
            response = self.client.get("/oauth2/login?next=/test/")
            self.assertEqual(response.status_code, 302)
            redir = urlparse(response["Location"])
            qs = parse_qs(redir.query)
            sq_expected = {
                "scope": ["openid"],
                "client_id": ["your-configured-client-id"],
                "state": ["L3Rlc3Qv"],
                "response_type": ["code"],
                "resource": ["your-adfs-RPT-name"],
                "redirect_uri": ["http://testserver/oauth2/callback"],
            }
            self.assertEqual(redir.scheme, "https")
            self.assertEqual(redir.hostname, "login.microsoftonline.com")
            self.assertEqual(
                redir.path.rstrip("/"),
                "/01234567-89ab-cdef-0123-456789abcdef/oauth2/authorize",
            )
            self.assertEqual(qs, sq_expected)

    @mock_adfs("azure")
    def test_oauth_redir_azure_version_two(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        settings.ENTRA_AUTH["VERSION"] = "v2.0"
        with (
            patch("django_entra_auth.config.django_settings", settings),
            patch("django_entra_auth.config.settings", Settings()),
            patch("django_entra_auth.views.provider_config", ProviderConfig()),
        ):
            response = self.client.get("/oauth2/login?next=/test/")
            self.assertEqual(response.status_code, 302)
            redir = urlparse(response["Location"])
            qs = parse_qs(redir.query)
            sq_expected = {
                "scope": ["openid api://your-adfs-RPT-name/.default"],
                "client_id": ["your-configured-client-id"],
                "state": ["L3Rlc3Qv"],
                "response_type": ["code"],
                "redirect_uri": ["http://testserver/oauth2/callback"],
            }
            self.assertEqual(redir.scheme, "https")
            self.assertEqual(redir.hostname, "login.microsoftonline.com")
            self.assertEqual(
                redir.path.rstrip("/"),
                "/01234567-89ab-cdef-0123-456789abcdef/oauth2/authorize",
            )
            self.assertEqual(qs, sq_expected)

    @mock_adfs("azure")
    def test_scopes_generated_correctly(self):
        from django_entra_auth.config import django_settings

        settings = deepcopy(django_settings)

        settings.ENTRA_AUTH["TENANT_ID"] = "dummy_tenant_id"
        settings.ENTRA_AUTH["VERSION"] = "v2.0"
        settings.ENTRA_AUTH["SCOPES"] = [
            "openid",
            "api://your-configured-client-id/user_impersonation",
        ]
        with (
            patch("django_entra_auth.config.django_settings", settings),
            patch("django_entra_auth.config.settings", Settings()),
            patch("django_entra_auth.views.provider_config", ProviderConfig()),
        ):
            response = self.client.get("/oauth2/login?next=/test/")
            self.assertEqual(response.status_code, 302)
            redir = urlparse(response["Location"])
            qs = parse_qs(redir.query)
            sq_expected = {
                "scope": ["openid api://your-configured-client-id/user_impersonation"],
                "client_id": ["your-configured-client-id"],
                "state": ["L3Rlc3Qv"],
                "response_type": ["code"],
                "redirect_uri": ["http://testserver/oauth2/callback"],
            }
            self.assertEqual(redir.scheme, "https")
            self.assertEqual(redir.hostname, "login.microsoftonline.com")
            self.assertEqual(
                redir.path.rstrip("/"),
                "/01234567-89ab-cdef-0123-456789abcdef/oauth2/authorize",
            )
            self.assertEqual(qs, sq_expected)
