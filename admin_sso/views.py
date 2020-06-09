from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect
from django.urls import reverse

from oauth2client.client import OAuth2WebServerFlow, FlowExchangeError
from github import Github

from admin_sso import settings

flow_kwargs = {
    "client_id": settings.DJANGO_ADMIN_SSO_OAUTH_CLIENT_ID,
    "client_secret": settings.DJANGO_ADMIN_SSO_OAUTH_CLIENT_SECRET,
    "scope": "email",
}
if settings.DJANGO_ADMIN_SSO_AUTH_URI:
    flow_kwargs["auth_uri"] = settings.DJANGO_ADMIN_SSO_AUTH_URI

if settings.DJANGO_ADMIN_SSO_TOKEN_URI:
    flow_kwargs["token_uri"] = settings.DJANGO_ADMIN_SSO_TOKEN_URI

if settings.DJANGO_ADMIN_SSO_REVOKE_URI:
    flow_kwargs["revoke_uri"] = settings.DJANGO_ADMIN_SSO_REVOKE_URI
if settings.DJANGO_ADMIN_SSO_BACKEND == "github":
    flow_kwargs["scope"] = "user:email"

flow_override = None


def start(request):
    flow = OAuth2WebServerFlow(
        redirect_uri=request.build_absolute_uri(
            reverse("admin:admin_sso_assignment_end")
        ),
        **flow_kwargs
    )

    return HttpResponseRedirect(flow.step1_get_authorize_url())


def end(request):
    if flow_override is None:
        flow = OAuth2WebServerFlow(
            redirect_uri=request.build_absolute_uri(
                reverse("admin:admin_sso_assignment_end")
            ),
            **flow_kwargs
        )
    else:
        flow = flow_override

    code = request.GET.get("code", None)
    if not code:
        return HttpResponseRedirect(reverse("admin:index"))
    try:
        credentials = flow.step2_exchange(code)
    except FlowExchangeError:
        return HttpResponseRedirect(reverse("admin:index"))

    email = None

    if settings.DJANGO_ADMIN_SSO_BACKEND == "github":
        g = Github(
            base_url=settings.DJANGO_ADMIN_SSO_GITHUB_BASE_URL,
            login_or_token=credentials.token_response.get('access_token'),
        )
        emails = g.get_user().get_emails()
        if len(emails) == 0:
            return HttpResponseRedirect(reverse("admin:index"))
        email = emails[0]['email']
        for e in emails:
            if e['primary']:
                email = e['email']
                break

    elif credentials.id_token["email_verified"]:
        email = credentials.id_token["email"]

    else:
        return HttpResponseRedirect(reverse("admin:index"))

    user = authenticate(sso_email=email)
    if user and user.is_active:
        login(request, user)
        return HttpResponseRedirect(reverse("admin:index"))

    # if anything fails redirect to admin:index
    return HttpResponseRedirect(reverse("admin:index"))
