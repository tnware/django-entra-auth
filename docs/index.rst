ADFS Authentication for Django
==============================

.. image:: https://readthedocs.org/projects/django-entra-auth/badge/?version=latest
    :target: http://django-entra-auth.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth
.. image:: https://img.shields.io/pypi/pyversions/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth#downloads
.. image:: https://img.shields.io/pypi/djversions/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth
.. image:: https://codecov.io/github/tnware/django-entra-auth/coverage.svg?branch=main
    :target: https://codecov.io/github/tnware/django-entra-auth?branch=main

A Django authentication backend for Microsoft ADFS and Azure AD

* Free software: BSD License
* Homepage: https://github.com/tnware/django-entra-auth
* Documentation: http://django-entra-auth.readthedocs.io/

Features
--------

* Integrates Django with Active Directory on Windows 2012 R2, 2016 or Azure AD in the cloud.
* Provides seamless single sign on (SSO) for your Django project on intranet environments.
* Auto creates users and adds them to Django groups based on info received from ADFS.
* Django Rest Framework (DRF) integration: Authenticate against your API with an ADFS access token.

Contents
--------

.. toctree::
    :maxdepth: 3

    install
    oauth2_explained
    settings_ref
    config_guides
    middleware
    token_lifecycle
    signals
    rest_framework
    demo
    troubleshooting
    faq
    contributing
