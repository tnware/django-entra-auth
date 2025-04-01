.. _install:

Installation
============

.. note::
   django-entra-auth is derived from `django-auth-adfs <https://github.com/snok/django-auth-adfs>`_
   created by Joris Beckers and contributors. While we've focused on Microsoft Entra ID specific
   functionality and added features like token lifecycle management, we're grateful to the original
   authors for their foundational work.

Requirements
------------

* Python 3.9 and above
* Django 4.2 and above

You will also need:

* A Microsoft Entra ID (formerly Azure AD) tenant
* An application registration in your Entra ID tenant with:
    * OpenID Connect authentication enabled
    * Appropriate redirect URIs configured
    * Required API permissions for Microsoft Graph (if using group synchronization)

.. note::
    When using Microsoft Entra ID, be aware of the following:

    * Users have no email address unless you assigned a Microsoft 365 license to that user
    * Groups are listed with their GUID in the groups claim, meaning you have to create your groups in Django using these GUIDs, instead of their name
    * Usernames are in the form of an email address, hence users created in Django follow this format
    * Claims are limited to those available in Entra ID, but can be extended using custom claims in app roles or optional claims

Package Installation
--------------------

Install via pip::

    pip install django-entra-auth

Django Configuration
-----------------

1. Add the authentication backend and app to your project's ``settings.py``:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        ...
        'django_entra_auth.backend.AdfsAuthCodeBackend',
        ...
    )

    INSTALLED_APPS = (
        ...
        # Required for OpenID Connect callback handling
        'django_entra_auth',
        ...
    )

2. Configure the Entra ID settings:

.. code-block:: python

    ENTRA_AUTH = {
        "CLIENT_ID": "your-application-id",
        "CLIENT_SECRET": "your-client-secret",
        "TENANT_ID": "your-tenant-id",
        # The audience should be your application ID
        "AUDIENCE": "your-application-id",
        # Map Entra ID claims to Django user fields
        "CLAIM_MAPPING": {
            "first_name": "given_name",
            "last_name": "family_name",
            "email": "upn"
        },
        # Optional: Enable group synchronization
        "GROUPS_CLAIM": "groups",
        "MIRROR_GROUPS": True,
    }

3. Configure login URLs:

.. code-block:: python

    # Configure Django to use Entra ID login
    LOGIN_URL = "django_entra_auth:login"
    LOGIN_REDIRECT_URL = "/"

4. Add the authentication URLs to your project's ``urls.py``:

.. code-block:: python

    urlpatterns = [
        ...
        path('oauth2/', include('django_entra_auth.urls')),
    ]

This adds the following endpoints:

* ``/oauth2/login`` - Initiates login with Entra ID
* ``/oauth2/login_no_sso`` - Forces login screen even if user is already authenticated
* ``/oauth2/callback`` - OpenID Connect callback URL (add this to your app registration's redirect URIs)
* ``/oauth2/logout`` - Logs out from both Django and Entra ID

Optional Configuration
--------------------

1. Enforce login for all views using middleware:

.. code-block:: python

    MIDDLEWARE = (
        ...
        # Forces login for all views unless specified in LOGIN_EXEMPT_URLS
        'django_entra_auth.middleware.LoginRequiredMiddleware',
    )

    # URLs that don't require authentication
    ENTRA_AUTH = {
        'LOGIN_EXEMPT_URLS': [
            '^$',  # Homepage
            '^about/',  # About page
        ],
    }

2. Custom login failure handling:

.. code-block:: python

    # Point to a custom view for login failures
    ENTRA_AUTH = {
        'CUSTOM_FAILED_RESPONSE_VIEW': 'myapp.views.custom_login_failed'
    }

3. Token lifecycle management:

.. code-block:: python

    MIDDLEWARE = [
        # ... other middleware
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_entra_auth.middleware.TokenLifecycleMiddleware',  # Add this line
        # ... other middleware
    ]

Template Integration
------------------

Add login/logout buttons to your templates:

.. code-block:: html+django

    {# Using POST requests (recommended) #}
    <form method="post" action="{% url 'django_entra_auth:logout' %}">
        {% csrf_token %}
        <button type="submit">Logout</button>
    </form>

    <form method="post" action="{% url 'django_entra_auth:login' %}">
        {% csrf_token %}
        <input type="hidden" name="next" value="{{ next }}">
        <button type="submit">Login</button>
    </form>

    {# Force login screen #}
    <form method="post" action="{% url 'django_entra_auth:login-no-sso' %}">
        {% csrf_token %}
        <input type="hidden" name="next" value="{{ next }}">
        <button type="submit">Login (no SSO)</button>
    </form>

    {# Using GET requests (alternative) #}
    <a href="{% url 'django_entra_auth:login' %}">Login</a>
    <a href="{% url 'django_entra_auth:login-no-sso' %}">Login (no SSO)</a>
    <a href="{% url 'django_entra_auth:logout' %}">Logout</a>

For more detailed configuration options, see the :ref:`settings` documentation.
