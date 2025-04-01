from django.urls import include, re_path

urlpatterns = [
    re_path(r"^oauth2/", include("django_entra_auth.urls")),
    re_path(r"^oauth2/", include("django_entra_auth.drf_urls")),
]
