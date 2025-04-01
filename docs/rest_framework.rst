Rest Framework Integration
==========================

Setup
-----

When using Django Rest Framework, you can authenticate your REST API clients using Microsoft Entra ID tokens.
This requires some additional configuration beyond the basic setup.

You'll need to install ``djangorestframework`` (or add it to your project dependencies)::

    pip install djangorestframework

The authentication backend will validate Entra ID access tokens for API requests.

Configuration Steps
------------------

1. Add the authentication class to Django Rest Framework in ``settings.py``:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'django_entra_auth.rest_framework.AdfsAccessTokenAuthentication',
            'rest_framework.authentication.SessionAuthentication',
        )
    }

2. Enable the token authentication backend in ``settings.py``:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        ...
        'django_entra_auth.backend.AdfsAccessTokenBackend',
        ...
    )

3. Prevent your API from triggering a login redirect:

.. code-block:: python

    ENTRA_AUTH = {
        'LOGIN_EXEMPT_URLS': [
            '^api',  # Assuming your API is available at /api
        ],
    }

4. (Optional) Override the standard Django Rest Framework login pages in your main ``urls.py``:

.. code-block:: python

    urlpatterns = [
        ...
        # The default rest framework urls shouldn't be included
        # If we include them, we'll end up with the DRF login page,
        # instead of being redirected to the Entra ID login page.
        #
        # path('api-auth/', include('rest_framework.urls')),
        #
        # This overrides the DRF login page
        path('oauth2/', include('django_entra_auth.drf_urls')),
        ...
    ]

Accessing the API
----------------

To access your API, clients need to obtain an access token from Microsoft Entra ID. Here's an example using the client credentials flow:

.. code-block:: python

    import requests
    from pprint import pprint

    # Get an access token from Microsoft Entra ID
    payload = {
        "grant_type": "client_credentials",
        "scope": "api://<your-application-id>/.default",
        "client_id": "<your-application-id>",
        "client_secret": "<your-client-secret>"
    }
    response = requests.post(
        "https://login.microsoftonline.com/<your-tenant-id>/oauth2/v2.0/token",
        data=payload
    )
    response.raise_for_status()
    response_data = response.json()
    access_token = response_data['access_token']

    # Make a request to your API using the access token
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access_token,
    }
    response = requests.get(
        'https://your-api.example.com/api/endpoint',
        headers=headers
    )
    pprint(response.json())

For more information on obtaining tokens and configuring API permissions, refer to:
* `Microsoft identity platform and OAuth 2.0 client credentials flow <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-credentials-grant-flow>`_
* The :ref:`token_lifecycle` documentation for managing tokens in your Django application
