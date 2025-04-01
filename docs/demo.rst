Demo
====
An example project is available to show what's needed to convert a Django project from form based
authentication to Microsoft Entra ID authentication.

Prerequisites
-------------
* A Microsoft Entra ID (Azure AD) tenant
* An application registration in your Entra ID tenant
* The example project code from the repository

Components
----------
The demo consists of a basic Django web application that demonstrates authentication with Microsoft Entra ID.
The application will run locally and authenticate against your Entra ID tenant.

Starting the environment
------------------------
1. Clone the repository
2. Install the requirements::

    pip install -r requirements.txt

3. Configure your Entra ID settings in the demo project's settings.py
4. Run the migrations::

    python manage.py migrate

5. Start the development server::

    python manage.py runserver

You should now be able to browse the demo project by opening the page `http://localhost:8000 <http://localhost:8000>`__
in a browser.

.. note::

    There are 2 versions of the web example. One is a forms based authentication example, the other depends on Entra ID.
    If you want to run the forms based example, use the files in the ``formsbased`` directory instead of the ``entra`` directory.

Using the demo
--------------
Once everything is up and running, you can click around in the basic poll app that the demo is.

* The bottom of the page shows details about the logged in user.
* Users will be created automatically in Django when they first log in through Entra ID.
* Users who are members of the "Django Admins" group in Entra ID will be made Django superusers.
* By default, only the page to vote on a poll requires you to be logged in.
* There are no questions by default. Create some in the admin section with a superuser account.
* Compare the files in the ``formsbased`` directory to those in the ``entra`` directory to see what was changed
  to enable Microsoft Entra ID authentication in a demo project.

Setting up Entra ID
------------------
1. Register a new application in the Azure Portal
2. Configure the redirect URI as http://localhost:8000/oauth2/callback
3. Generate a client secret
4. Note down the following values:
   * Application (client) ID
   * Directory (tenant) ID
   * Client secret
5. Update these values in the demo project's settings.py
