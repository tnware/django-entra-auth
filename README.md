# Entra ID Authentication for Django

> **Attribution**: This project is a fork of [django-auth-adfs](https://github.com/snok/django-auth-adfs) created by Joris Beckers and maintained by [Snok](https://github.com/snok).

[![docs](https://github.com/tnware/django-entra-auth/actions/workflows/docs_deploy.yml/badge.svg)](https://github.com/tnware/django-entra-auth/actions/workflows/docs_deploy.yml)
[![PyPI version](https://img.shields.io/pypi/v/django-entra-auth.svg)](https://pypi.python.org/pypi/django-entra-auth)
[![Python versions](https://img.shields.io/pypi/pyversions/django-entra-auth.svg)](https://pypi.python.org/pypi/django-entra-auth#downloads)
[![Django versions](https://img.shields.io/pypi/djversions/django-entra-auth.svg)](https://pypi.python.org/pypi/django-entra-auth)
[![License](https://img.shields.io/pypi/l/django-entra-auth.svg)](https://github.com/tnware/django-entra-auth/blob/main/LICENSE)
[![Tests](https://github.com/tnware/django-entra-auth/actions/workflows/testing.yml/badge.svg)](https://github.com/tnware/django-entra-auth/actions/workflows/testing.yml)

A Django authentication backend for Microsoft Entra ID (formerly Azure AD). This project extends the foundation established by `django-auth-adfs` with specialized focus on Entra ID and Graph API integration.

*   Free software: BSD License
*   Homepage: https://github.com/tnware/django-entra-auth
*   Documentation: https://tnware.github.io/django-entra-auth

## Features

*   Integrates Django with Microsoft Entra ID (formerly Azure AD)
*   Provides seamless single sign on (SSO) for your Django project
*   Auto creates users and adds them to Django groups based on info received from Entra ID
*   **Token Lifecycle Management** (new): Automatically handles storing, refreshing, and encrypting access/refresh tokens
*   **On-Behalf-Of Token Support** (new): Simplifies access to Microsoft Graph API and other delegated access scenarios
*   Django Rest Framework (DRF) integration: Authenticate against your API with an Entra ID access token

While building on the original django-auth-adfs, we've focused specifically on the Entra ID authentication scenario with enhancements for token management, storing them so that your application can securely and seamlessly delegate access to Graph API on behalf of your users.

## Installation

Python package:

```bash
pip install django-entra-auth
```

In your project's `settings.py` add these settings.

```python
AUTHENTICATION_BACKENDS = (
    ...
    'django_entra_auth.backend.AdfsAuthCodeBackend',
    ...
)

INSTALLED_APPS = (
    ...
    # Needed for the auth redirect URI and static files to function
    'django_entra_auth',
    ...
)

# Basic configuration for Entra ID
# checkout the documentation for more settings
ENTRA_AUTH = {
    # For Entra ID, use 'login.microsoftonline.com/<your-tenant-id>'
    "SERVER": "login.microsoftonline.com/<your-tenant-id>",
    "CLIENT_ID": "your-application-client-id",
    "RELYING_PARTY_ID": "your-application-client-id", # Often same as CLIENT_ID for Entra ID
    # OIDC Audience ("aud" claim). For Entra ID, LIENT_ID
    "AUDIENCE": "your-application-client-id",
    # Set to False for Entra ID. Provide path for ADFS.
    "CA_BUNDLE": False,
    "CLAIM_MAPPING": {"first_name": "given_name",
                      "last_name": "family_name",
                      "email": "email"}, # Adjust based on claims from your provider
    # See documentation for TokenLifecycleMiddleware settings like:
    # "TOKEN_REFRESH_THRESHOLD", "STORE_OBO_TOKEN", "TOKEN_ENCRYPTION_SALT",
    # "LOGOUT_ON_TOKEN_REFRESH_FAILURE"
}

# Configure django to redirect users to the right URL for login
LOGIN_URL = "django_entra_auth:login"
LOGIN_REDIRECT_URL = "/" # Or wherever users should land after login

########################
# OPTIONAL SETTINGS
########################

MIDDLEWARE = (
    ...
    # Optional: Automatically manage access/refresh/OBO tokens in the session
    # Must be AFTER SessionMiddleware and AuthenticationMiddleware
    'django_entra_auth.middleware.TokenLifecycleMiddleware',
    # With this you can force a user to login without using
    # the LoginRequiredMixin on every view class
    #
    # You can specify URLs for which login is not enforced by
    # specifying them in the LOGIN_EXEMPT_URLS setting.
    'django_entra_auth.middleware.LoginRequiredMiddleware',
)

# Specify URLs exempt from LoginRequiredMiddleware (if used)
# LOGIN_EXEMPT_URLS = (
#     r'^/about/.*$',
#     r'^/legal/.*$',
# )
```

In your project's `urls.py` add these paths:

```python
from django.urls import path, include

urlpatterns = [
    ...
    path('oauth2/', include('django_entra_auth.urls')),
]
```

This will add these paths to Django:

*   `/oauth2/login` where users are redirected to, to initiate the login with the identity provider.
*   `/oauth2/login_no_sso` where users are redirected to, but forcing a login screen.
*   `/oauth2/callback` where the identity provider redirects back to after login. Ensure your redirect URI in Entra ID/ADFS is set to this.
*   `/oauth2/logout` which logs out the user from both Django and the identity provider (if supported by provider).

Below is sample Django template code to use these paths depending if
you'd like to use GET or POST requests. Logging out via GET was deprecated in
[Django 4.1](https://docs.djangoproject.com/en/5.1/releases/4.1/#features-deprecated-in-4-1).

*   Using GET requests (Login only):

    ```html
    {# Logout requires POST #}
    <a href="{% url 'django_entra_auth:login' %}">Login</a>
    <a href="{% url 'django_entra_auth:login-no-sso' %}">Login (no SSO)</a>
    ```

*   Using POST requests:

    ```html+django
    <form method="post" action="{% url 'django_entra_auth:logout' %}">
        {% csrf_token %}
        <button type="submit">Logout</button>
    </form>
    <form method="post" action="{% url 'django_entra_auth:login' %}">
        {% csrf_token %}
        <input type="hidden" name="next" value="{{ next }}">
        <button type="submit">Login</button>
    </form>
    <form method="post" action="{% url 'django_entra_auth:login-no-sso' %}">
        {% csrf_token %}
        <input type="hidden" name="next" value="{{ next }}">
        <button type="submit">Login (no SSO)</button>
    </form>
    ```

## Contributing

Contributions to the code are more then welcome.
For more details have a look at the `CONTRIBUTING.rst` file.