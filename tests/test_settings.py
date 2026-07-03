import sys
from copy import deepcopy

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, SimpleTestCase, override_settings
from mock import Mock, patch
from requests import HTTPError
from django_entra_auth.config import django_settings
from django_entra_auth.config import ConfigLoadError
from django_entra_auth.config import Settings
from django_entra_auth.config import ProviderConfig
from .custom_config import Settings as CustomSettings


class SettingsTests(TestCase):
    def test_no_settings(self):
        settings = deepcopy(django_settings)
        del settings.ENTRA_AUTH
        with patch("django_entra_auth.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_claim_mapping_overlapping_username_field(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["CLAIM_MAPPING"] = {"username": "samaccountname"}
        with patch("django_entra_auth.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_tenant_and_server(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["TENANT_ID"] = "abc"
        settings.ENTRA_AUTH["SERVER"] = "abc"
        with patch("django_entra_auth.config.django_settings", settings):
            config = Settings()
            self.assertEqual(config.SERVER, "abc")

    def test_no_tenant_id(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["SERVER"] = "abc"
        del settings.ENTRA_AUTH["TENANT_ID"]
        with patch("django_entra_auth.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_no_tenant_but_block_guest(self):
        # This test is no longer relevant as TENANT_ID is required
        pass

    def test_tenant_with_block_users(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["TENANT_ID"] = "abc"
        settings.ENTRA_AUTH["BLOCK_GUEST_USERS"] = True
        with patch("django_entra_auth.config.django_settings", settings):
            current_settings = Settings()
            self.assertTrue(current_settings.BLOCK_GUEST_USERS)

    def test_unknown_setting(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["dummy"] = "abc"
        with patch("django_entra_auth.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_required_setting(self):
        settings = deepcopy(django_settings)
        del settings.ENTRA_AUTH["AUDIENCE"]
        with patch("django_entra_auth.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_default_failed_response_setting(self):
        settings = deepcopy(django_settings)
        with patch("django_entra_auth.config.django_settings", settings):
            s = Settings()
            self.assertTrue(callable(s.CUSTOM_FAILED_RESPONSE_VIEW))

    def test_dotted_path_failed_response_setting(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["CUSTOM_FAILED_RESPONSE_VIEW"] = (
            "tests.views.test_failed_response"
        )
        with patch("django_entra_auth.config.django_settings", settings):
            s = Settings()
            self.assertTrue(callable(s.CUSTOM_FAILED_RESPONSE_VIEW))

    def test_settings_version(self):
        settings = deepcopy(django_settings)
        current_settings = Settings()
        self.assertEqual(current_settings.VERSION, "v1.0")
        settings.ENTRA_AUTH["TENANT_ID"] = "abc"
        settings.ENTRA_AUTH["VERSION"] = "v2.0"
        with patch("django_entra_auth.config.django_settings", settings):
            current_settings = Settings()
            self.assertEqual(current_settings.VERSION, "v2.0")

    def test_version_setting(self):
        settings = deepcopy(django_settings)
        settings.ENTRA_AUTH["TENANT_ID"] = "abc"
        settings.ENTRA_AUTH["VERSION"] = "v2.0"
        with patch("django_entra_auth.config.django_settings", settings):
            config = Settings()
            self.assertEqual(config.VERSION, "v2.0")

    def test_openid_config_uses_configured_server(self):
        settings = Settings()
        settings.CLIENT_ID = "client"
        settings.SERVER = "login.microsoftonline.us"
        settings.TENANT_ID = "tenant"

        with patch("django_entra_auth.config.settings", settings):
            provider_config = ProviderConfig()

            response = Mock()
            response.raise_for_status.side_effect = HTTPError()
            provider_config.session.get = Mock(return_value=response)

            with self.assertRaises(ConfigLoadError):
                provider_config._load_openid_config()

            provider_config.session.get.assert_called_once_with(
                "https://login.microsoftonline.us/tenant/.well-known/openid-configuration?appid=client",
                timeout=settings.TIMEOUT,
            )

    def test_configured_proxy(self):
        settings = Settings()
        settings.PROXIES = {"http": "10.0.0.1"}
        with patch("django_entra_auth.config.settings", settings):
            provider_config = ProviderConfig()
            self.assertEqual(provider_config.session.proxies, {"http": "10.0.0.1"})

    def test_no_configured_proxy(self):
        provider_config = ProviderConfig()
        self.assertIsNone(provider_config.session.proxies)


class CustomSettingsTests(SimpleTestCase):
    def setUp(self):
        sys.modules.pop("django_entra_auth.config", None)

    def tearDown(self):
        sys.modules.pop("django_entra_auth.config", None)

    def test_dotted_path(self):
        auth_adfs = deepcopy(django_settings).ENTRA_AUTH
        auth_adfs["SETTINGS_CLASS"] = "tests.custom_config.Settings"

        with override_settings(ENTRA_AUTH=auth_adfs):
            from django_entra_auth.config import settings

            self.assertIsInstance(settings, CustomSettings)
