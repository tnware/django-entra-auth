.. _settings:

Settings Reference
==================

.. _audience_setting:

AUDIENCE
--------
* **Default**: ``None``
* **Type**: ``string``

**Required**

Set this to the value of the ``aud`` claim your Microsoft Entra ID application sends back in the JWT token.
This is typically your application ID (client ID).

.. _block_guest_users_setting:

BLOCK_GUEST_USERS
-----------------
* **Default**: ``False``
* **Type**: ``boolean``

Whether guest users of your Microsoft Entra ID tenant are allowed to log into the site. This is validated by matching
the ``http://schemas.microsoft.com/identity/claims/tenantid`` claim in the token against the configured tenant.

.. _boolean_claim_mapping_setting:

BOOLEAN_CLAIM_MAPPING
---------------------
* **Default**: ``None``
* **Type**: ``dictionary``

A dictionary of claim/field mappings that is used to set boolean fields on the user account in Django.

The **key** represents user model field (e.g. ``is_staff``)
and the **value** represents the claim name (e.g. ``user_is_staff``).

If the value is any of ``y, yes, t, true, on, 1``, the field will be set to ``True``. All other values, or the absence of
the claim, will result in a value of ``False``

example:

.. code-block:: python

    ENTRA_AUTH = {
        "BOOLEAN_CLAIM_MAPPING": {
            "is_staff": "user_is_staff",
            "is_superuser": "user_is_superuser"
        },
    }

CA_BUNDLE
---------
* **Default**: ``True``
* **Type**: ``boolean`` or ``string``

The value of this setting is passed to the ``requests`` package when fetching tokens from Entra ID.
It allows you to control the webserver certificate verification of the Entra ID server.

``True`` to use the default CA bundle of the ``requests`` package.

``/path/to/ca-bundle.pem`` allows you to specify a path to a CA bundle file.

``False`` disables the certificate check.

.. warning::
    Do not set this value to ``False`` in a production setup. This could lead to security issues
    as we load certain settings from Entra ID.

.. _claim_mapping_setting:

CLAIM_MAPPING
-------------
* **Default**: ``None``
* **Type**: ``dictionary``

A dictionary of claim/field mappings that will be used to populate the user account in Django.
The user's details will be set according to this setting upon each login.

The **key** represents the user model field (e.g. ``first_name``)
and the **value** represents the claim name (e.g. ``given_name``).

example:

.. code-block:: python

    ENTRA_AUTH = {
        "CLAIM_MAPPING": {
            "first_name": "given_name",
            "last_name": "family_name",
            "email": "upn"
        },
    }

The dictionary can also map extra details to the Django user account using an
`Extension of the User model <https://docs.djangoproject.com/en/stable/topics/auth/customizing/#extending-the-existing-user-model>`_

Set a dictionary as value in the CLAIM_MAPPING setting with the key being the name of the User model.
You will need to make sure the related field exists before the user authenticates.
This can be done by creating a receiver on the
`post_save <https://docs.djangoproject.com/en/4.0/ref/signals/#post-save>`_ signal that
creates the related instance when the ``User`` instance is created.

example:

.. code-block:: python

    'CLAIM_MAPPING': {
        'first_name': 'given_name',
        'last_name': 'family_name',
        'email': 'upn',
        'userprofile': {
            'employee_id': 'employeeid'
        }
    }

.. _client_id_setting:

CLIENT_ID
---------
* **Default**: ``None``
* **Type**: ``string``

**Required**

Set this to the Application (client) ID value from your registered application in the Azure Portal.

CLIENT_SECRET
-------------
* **Default**: ``None``
* **Type**: ``string``

**Required**

The client secret generated for your application in the Azure Portal under Certificates & secrets.

CONFIG_RELOAD_INTERVAL
----------------------
* **Default**: ``24``
* **Unit**: hours
* **Type**: ``integer``

When starting Django, some settings are retrieved from the Entra ID OpenID Connect configuration.
Based on this information, certain configuration for this module is calculated.

This setting determines the interval after which the configuration is reloaded.

.. _create_new_users_setting:

CREATE_NEW_USERS
----------------
* **Default**: ``True``
* **Type**: ``boolean``

Determines whether users are created automatically if they do not exist.

If set to ``False``, then you need to create your users before they can log in.

DISABLE_SSO
-----------
* **Default**: ``False``
* **Type**: ``boolean``

Setting this to ``True`` will globally disable the seamless single sign-on capability of Entra ID.
This forces Entra ID to prompt users for authentication instead of automatically logging them in
with their current session.

You can also selectively enable this setting by using ``<a href="{% url 'django_entra_auth:login-no-sso' %}">...</a>``
in a template instead of the regular ``<a href="{% url 'django_entra_auth:login' %}">...</a>``

.. _groups_claim_setting:

GROUPS_CLAIM
------------
* **Default**: ``groups``
* **Type**: ``string``

Name of the claim in the JWT token that contains the groups the user is member of.
If an entry in this claim matches a group configured in Django, the user will join it automatically.

If there are too many groups to fit in the JWT token, the application will make a request to the
Microsoft Graph API to find the groups. If you have many groups but only need a specific few,
you can customize the request by overriding ``AdfsBaseBackend.get_group_memberships_from_ms_graph_params``
and specifying the `OData query parameters <https://learn.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=python#http-request>`_.

Set this setting to ``None`` to disable automatic group handling. The group memberships of the user
will not be touched.

.. IMPORTANT::
   If not set to ``None``, a user's group membership in Django will be reset to match this claim's value.
   If there's no value in the access token, the user will be removed from all groups.

JWT_LEEWAY
---------
* **Default**: ``0``
* **Type**: ``integer``
* **Unit**: seconds

Sets the leeway value for JWT token validation. This allows some clock skew between your server and the Entra ID server when validating timestamps in the token.

The leeway value is added to the expiration time (``exp`` claim) during token validation to provide a grace period, which can help prevent authentication failures due to minor clock synchronization issues.

Example:

.. code-block:: python

    ENTRA_AUTH = {
        # Add a 30 second leeway for token validation
        "JWT_LEEWAY": 30,
    }

GROUP_TO_FLAG_MAPPING
---------------------
* **Default**: ``None``
* **Type**: ``dictionary``

This settings allows you to set flags on a user based on their group membership in Entra ID.

For example, if a user is a member of the group ``Django Staff``, you can automatically set the ``is_staff``
field of the user to ``True``.

The **key** represents the boolean user model field (e.g. ``is_staff``)
and the **value**, which can either be a single String or an array of Strings, represents the group(s) name (e.g. ``Django Staff``).

example:

.. code-block:: python

    ENTRA_AUTH = {
        "GROUP_TO_FLAG_MAPPING": {
            "is_staff": ["Django Staff", "Other Django Staff"],
            "is_superuser": "Django Admins"
        },
    }

.. NOTE::
   The group doesn't need to exist in Django for this to work. This will work as long as it's in the groups claim
   in the access token.

GUEST_USERNAME_CLAIM
--------------------
* **Default**: ``None``
* **Type**: ``string``

When these criteria are met:

1. A ``guest_username_claim`` is configured
2. Token claims do not have the configured ``settings.USERNAME_CLAIM`` in it
3. The ``settings.BLOCK_GUEST_USERS`` is set to ``False``
4. The claims ``tid`` does not match ``settings.TENANT_ID`` or claims ``idp`` does not match ``iss``.

Then, the ``GUEST_USERNAME_CLAIM`` can be used to populate a username, when the ``USERNAME_CLAIM`` cannot be found in
the claims.

This can be useful when you want to use ``upn`` as a username claim for your own users,
but some guest users (such as normal outlook users) don't have that claim.

LOGIN_EXEMPT_URLS
-----------------
* **Default**: ``None``
* **Type**: ``list``

When you activate the ``LoginRequiredMiddleware`` middleware, by default every page will redirect
an unauthenticated user to the page configured in the Django setting ``LOGIN_URL``.

If you have pages that should not trigger this redirect, add them to this setting as a list value.

Every item it the list is interpreted as a regular expression.

example:

.. code-block:: python

    ENTRA_AUTH = {
        'LOGIN_EXEMPT_URLS': [
            '^$',
            '^api'
        ],
    }

.. _mirror_group_setting:

MIRROR_GROUPS
-------------
* **Default**: ``False``
* **Type**: ``boolean``

This parameter will create groups from Entra ID in the Django database if they do not exist already.

``True`` will create groups.

``False`` will not create any extra groups.

.. IMPORTANT::
    This parameter only has effect if GROUP_CLAIM is set to something other then ``None``.

.. _retries_setting:

RETRIES
-------
* **Default**: ``3``
* **Type**: ``integer``

The number of time a request to the Entra ID server is retried. It allows, in combination with :ref:`timeout_setting`
to fine tune the behaviour of the connection to Entra ID.

SCOPES
------
* **Default**: ``[]``
* **Type**: ``list``

Additional scopes to request during authentication. By default, the library requests the necessary scopes
for OpenID Connect authentication.

SETTINGS_CLASS
--------------
* **Default**: ``django_entra_auth.config.Settings``
* **Type**: ``string``

By default, django-entra-auth reads the configuration from the Django setting
``ENTRA_AUTH``. You can provide the configuration in a custom implementation
and point to it by using the ``SETTINGS_CLASS`` setting:

.. code-block:: python

    # in myapp.auth.config

    class CustomSettings:
        CLIENT_ID = 'foo'
        CLIENT_SECRET = 'bar'
        TENANT_ID = 'baz'
        ...

    # in settings.py

    ENTRA_AUTH = {
        'SETTINGS_CLASS': 'myapp.auth.config.CustomSettings',
        # other settings are not needed
    }

The value must be an importable dotted Python path, and the imported object
must be callable with no arguments to initialize.

Use cases are storing configuration in database so an administrator can edit
the configuration in an admin interface.

.. _tenant_id_setting:

TENANT_ID
---------
* **Default**: ``None``
* **Type**: ``string``

**Required**

The tenant ID (Directory ID) of your Microsoft Entra ID instance.

.. _timeout_setting:

TIMEOUT
-------
* **Default**: ``5``
* **Unit**: seconds
* **Type**: ``integer``

The timeout in seconds for every request made to the Entra ID server. It's passed on as the ``timeout`` parameter
to the underlying calls to the `requests <http://docs.python-requests.org/en/master/user/quickstart/#timeouts>`__
library.

It allows, in combination with :ref:`retries_setting` to fine tune the behaviour of the connection to Entra ID.

.. _username_claim_setting:

USERNAME_CLAIM
--------------
* **Default**: ``upn``
* **Type**: ``string``

Name of the claim sent in the JWT token that contains the username.
If the user doesn't exist yet, this field will be used as their username.

The value of the claim must be unique. No 2 users should ever have the same value.

.. warning::
   You shouldn't need to change this value as ``upn`` maps to the ``UserPrincipleName``,
   which is unique in Entra ID.

.. _version_setting:

VERSION
--------------
* **Default**: ``v2.0``
* **Type**: ``string``

Version of the Microsoft Entra ID endpoint version. By default it is set to ``v2.0``.
For new projects, ``v2.0`` is recommended.

PROXIES
-------
* **Default**: ``None``
* **Type**: ``dict``

An optional proxy for all communication with the server. Example: ``{'http': '10.0.0.1', 'https': '10.0.0.2'}``
See the `requests documentation <https://requests.readthedocs.io/en/v3.0.0/api/#requests.Session.proxies>`__ for more information.

TOKEN_REFRESH_THRESHOLD
---------------------------
* **Default**: ``300`` (5 minutes)
* **Type**: ``integer``
* **Unit**: seconds

Used by the ``TokenLifecycleMiddleware`` to determine how long before token expiration to attempt a refresh.
This setting controls how proactively the middleware will refresh tokens before they expire.

For example, with the default value of 300 seconds (5 minutes), if a token is set to expire in 4 minutes,
the middleware will attempt to refresh it during the next request. This helps ensure that users don't
experience disruptions due to token expiration during active sessions.

.. code-block:: python

    # In your Django settings.py
    # Refresh tokens 10 minutes before they expire
    ENTRA_AUTH = {
        # other settings
        "TOKEN_REFRESH_THRESHOLD": 600
    }

STORE_OBO_TOKEN
------------------
* **Default**: ``True``
* **Type**: ``boolean``

Used by the ``TokenLifecycleMiddleware`` to enable or disable the storage of On-Behalf-Of (OBO) tokens
for Microsoft Graph API. Set to ``False`` if you don't need to access Microsoft Graph API.

.. note::
   When using the ``TokenLifecycleMiddleware`` with Django's ``signed_cookies`` session backend, token storage
   is always disabled for security reasons. This behavior cannot be overridden. If you need token storage,
   you must use a different session backend like database or cache-based sessions.

TOKEN_ENCRYPTION_SALT
--------------------------
* **Default**: ``b"django_entra_auth_token_encryption"``
* **Type**: ``string``

Used by the ``TokenLifecycleMiddleware`` to derive an encryption key for token encryption.
The salt is combined with Django's ``SECRET_KEY`` to create a unique encryption key.

You can customize this value to use a different salt for token encryption:

.. code-block:: python

    # In your Django settings.py
    ENTRA_AUTH = {
        # other settings
        "TOKEN_ENCRYPTION_SALT": "your-custom-salt-string"
    }

.. warning::
   If you change this setting after tokens have been stored in sessions, those tokens will no longer be decryptable.
   This effectively invalidates all existing tokens, requiring users to re-authenticate.
   Consider this when deploying changes to the salt in production environments.

LOGOUT_ON_TOKEN_REFRESH_FAILURE
-------------------------------
* **Default**: ``False``
* **Type**: ``boolean``

Used by the ``TokenLifecycleMiddleware`` to control whether users should be automatically logged out when token refresh fails.

When set to ``True``, if a token refresh attempt fails (either due to an error response from the server or an exception),
the middleware will automatically log the user out of the Django application.

When set to ``False`` (the default), the middleware will log the error but allow the user to continue using the application
until their session expires naturally, even though their tokens are no longer valid.

This setting is particularly important for security considerations, as it determines how your application responds when a user's account
has been disabled in Entra ID. When enabled, it can help ensure that users who have had their accounts disabled in the
identity provider are promptly logged out of your Django application, closing a potential security gap.

This feature is disabled by default to prioritize user experience, but can be enabled for applications where security requirements
outweigh the potential disruption of unexpected logouts.

.. code-block:: python

    # In your Django settings.py
    ENTRA_AUTH = {
        # other settings
        "LOGOUT_ON_TOKEN_REFRESH_FAILURE": True
    }

.. note::
   This setting only affects what happens when token refresh fails. It does not affect the initial authentication process
   or what happens when tokens expire without a refresh attempt.

.. important::
   Even for applications that don't make additional API calls after authentication, enabling this setting provides
   an optional security mechanism that can help ensure that access revocation in Entra ID is reflected in your
   Django application.
