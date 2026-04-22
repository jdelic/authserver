from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from oauth2_provider.models import get_application_model
from authserver.selfservice_forms import EmailAliasCreateForm, MailingListSettingsForm, SelfServiceAuthenticationForm, \
    ServiceUserCreateForm
from mailauth.models import EmailAlias, MailingList, MNServiceUser, MNUser


SERVICE_USER_SESSION_KEY = "authserver_service_user_login"
SERVICE_USER_USERNAME_SESSION_KEY = "authserver_service_user_username"


class AuthPageContextMixin:
    homepage_template_name = "registration/home.html"
    login_template_name = "registration/login.html"

    def get_next_target(self, request: HttpRequest, fallback: str = "/") -> str:
        if request.method == "POST":
            return request.POST.get("next", "") or fallback
        return request.GET.get("next", "") or fallback

    def get_login_flow_metadata(self, next_target: str) -> Optional[dict[str, str]]:
        parsed = urlsplit(next_target or "/")
        if not parsed.path.startswith("/o2/authorize"):
            return None

        client_id = parse_qs(parsed.query).get("client_id", [None])[0]
        application_name = None
        if client_id:
            application = get_application_model().objects.filter(client_id=client_id).only("name").first()
            if application is not None:
                application_name = application.name

        return {
            "eyebrow": "OpenID Connect",
            "title": "Sign in to continue",
            "description": (
                f"You are signing in to {application_name}."
                if application_name
                else "You are signing in to an OpenID Connect application."
            ),
            "application_name": application_name or "Requested application",
        }

    def build_auth_page_context(
        self,
        request: HttpRequest,
        next_target: Optional[str] = None,
        form: Optional[SelfServiceAuthenticationForm] = None,
    ) -> dict[str, Any]:
        resolved_next = next_target or self.get_next_target(request)
        return {
            "form": form if form is not None else SelfServiceAuthenticationForm(request=request, initial={"next": resolved_next}),
            "next": resolved_next,
            "login_flow": self.get_login_flow_metadata(resolved_next),
        }


class DashboardContextMixin:
    dashboard_template_name = "selfservice/dashboard.html"

    def get_aliases(self, user: MNUser) -> QuerySet[EmailAlias]:
        return EmailAlias.objects.filter(user=user).select_related("domain").order_by("domain__name", "mailprefix")

    def get_mailing_lists(self, user: MNUser) -> QuerySet[EmailAlias]:
        return (
            EmailAlias.objects.filter(forward_to__owner=user)
            .select_related("domain", "forward_to")
            .order_by("domain__name", "mailprefix")
        )

    def get_service_users(self, user: MNUser) -> QuerySet[MNServiceUser]:
        return MNServiceUser.objects.filter(user=user).order_by("username")

    def get_dashboard_context(
        self,
        request: HttpRequest,
        alias_form: Optional[EmailAliasCreateForm] = None,
        service_user_form: Optional[ServiceUserCreateForm] = None,
    ) -> dict[str, Any]:
        user = request.user
        return {
            "alias_form": alias_form if alias_form is not None else EmailAliasCreateForm(user),
            "service_user_form": (
                service_user_form if service_user_form is not None else ServiceUserCreateForm(user)
            ),
            "aliases": self.get_aliases(user),
            "mailing_lists": self.get_mailing_lists(user),
            "service_users": self.get_service_users(user),
        }

    def render_dashboard(
        self,
        request: HttpRequest,
        alias_form: Optional[EmailAliasCreateForm] = None,
        service_user_form: Optional[ServiceUserCreateForm] = None,
        status: int = 200,
    ) -> HttpResponse:
        return render(
            request,
            self.dashboard_template_name,
            self.get_dashboard_context(
                request,
                alias_form=alias_form,
                service_user_form=service_user_form,
            ),
            status=status,
        )


class SelfServiceAccessMixin(LoginRequiredMixin):
    login_url = "authserver-login"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if request.session.get(SERVICE_USER_SESSION_KEY):
            messages.error(
                request,
                "Service user credentials cannot access the self-service portal.",
            )
            logout(request)
            return redirect("/")

        if request.user.is_authenticated and request.user.is_staff:
            return redirect("/admin/")

        return super().dispatch(request, *args, **kwargs)


class HomeView(AuthPageContextMixin, DashboardContextMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return render(request, self.homepage_template_name, self.build_auth_page_context(request, next_target="/"))

        if request.session.get(SERVICE_USER_SESSION_KEY):
            messages.error(request, "Service user credentials cannot access the self-service portal.")
            logout(request)
            return redirect("/")

        if request.user.is_staff:
            return redirect("/admin/")

        return self.render_dashboard(request)


class DashboardView(SelfServiceAccessMixin, DashboardContextMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        return self.render_dashboard(request)


class SelfServiceLoginView(AuthPageContextMixin, LoginView):
    authentication_form = SelfServiceAuthenticationForm
    template_name = AuthPageContextMixin.login_template_name
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context.update(
            self.build_auth_page_context(
                self.request,
                next_target=self.get_redirect_url() or "/",
                form=context.get("form"),
            )
        )
        return context

    def get_success_url(self) -> str:
        if self.request.user.is_staff:
            return "/admin/"
        return self.get_redirect_url() or reverse("selfservice-dashboard")

    def form_valid(self, form: SelfServiceAuthenticationForm) -> HttpResponse:
        response = super().form_valid(form)
        if form.service_user is not None:
            self.request.session[SERVICE_USER_SESSION_KEY] = True
            self.request.session[SERVICE_USER_USERNAME_SESSION_KEY] = form.service_user.username
        else:
            self.request.session.pop(SERVICE_USER_SESSION_KEY, None)
            self.request.session.pop(SERVICE_USER_USERNAME_SESSION_KEY, None)
        return response


class SelfServiceLogoutView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        messages.success(request, "You have been logged out.")
        return redirect("/")


class EmailAliasCreateView(SelfServiceAccessMixin, DashboardContextMixin, View):
    def post(self, request: HttpRequest) -> HttpResponse:
        form = EmailAliasCreateForm(request.user, request.POST)
        if form.is_valid():
            alias = form.save()
            messages.success(request, f"Created alias {alias.mailprefix}@{alias.domain.name}.")
            return redirect("selfservice-dashboard")
        return self.render_dashboard(request, alias_form=form, status=400)


class EmailAliasActionMixin(SelfServiceAccessMixin):
    def get_owned_alias(self, alias_id: int, request: HttpRequest) -> EmailAlias:
        return get_object_or_404(EmailAlias.objects.select_related("domain"), pk=alias_id, user=request.user)


class EmailAliasBlockToggleView(EmailAliasActionMixin, View):
    blacklisted = True

    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_alias(alias_id, request)
        alias.blacklisted = self.blacklisted
        alias.save(update_fields=["blacklisted"])
        action = "Blocked" if self.blacklisted else "Unblocked"
        messages.success(request, f"{action} {alias.mailprefix}@{alias.domain.name}.")
        return redirect("selfservice-dashboard")


class EmailAliasDeleteView(EmailAliasActionMixin, View):
    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_alias(alias_id, request)
        if request.user.delivery_mailbox_id == alias.id:
            messages.error(request, "You cannot delete your primary delivery alias.")
            return redirect("selfservice-dashboard")
        alias_address = f"{alias.mailprefix}@{alias.domain.name}"
        alias.delete()
        messages.success(request, f"Deleted alias {alias_address}.")
        return redirect("selfservice-dashboard")


class EmailAliasBulkActionView(EmailAliasActionMixin, View):
    def post(self, request: HttpRequest) -> HttpResponse:
        action = request.POST.get("action", "")
        alias_ids: list[int] = []
        for value in request.POST.getlist("alias_ids"):
            try:
                alias_id = int(value)
            except (TypeError, ValueError):
                continue
            if alias_id not in alias_ids:
                alias_ids.append(alias_id)

        if action not in {"block", "unblock", "delete"}:
            messages.error(request, "Unknown bulk action.")
            return redirect("selfservice-dashboard")

        if not alias_ids:
            messages.error(request, "Select at least one alias first.")
            return redirect("selfservice-dashboard")

        aliases = list(
            EmailAlias.objects.select_related("domain")
            .filter(user=request.user, pk__in=alias_ids)
            .order_by("domain__name", "mailprefix")
        )
        if not aliases:
            messages.error(request, "None of the selected aliases are available.")
            return redirect("selfservice-dashboard")

        if action == "block":
            EmailAlias.objects.filter(pk__in=[alias.id for alias in aliases]).update(blacklisted=True)
            messages.success(request, f"Blocked {len(aliases)} alias{'es' if len(aliases) != 1 else ''}.")
            return redirect("selfservice-dashboard")

        if action == "unblock":
            EmailAlias.objects.filter(pk__in=[alias.id for alias in aliases]).update(blacklisted=False)
            messages.success(request, f"Unblocked {len(aliases)} alias{'es' if len(aliases) != 1 else ''}.")
            return redirect("selfservice-dashboard")

        deleted_count = 0
        skipped_primary = 0
        for alias in aliases:
            if request.user.delivery_mailbox_id == alias.id:
                skipped_primary += 1
                continue
            alias.delete()
            deleted_count += 1

        if deleted_count:
            messages.success(request, f"Deleted {deleted_count} alias{'es' if deleted_count != 1 else ''}.")
        if skipped_primary:
            messages.warning(
                request,
                f"Skipped {skipped_primary} primary delivery alias{'es' if skipped_primary != 1 else ''}.",
            )
        return redirect("selfservice-dashboard")


class MailingListBaseView(SelfServiceAccessMixin, View):
    template_name = "selfservice/mailing_list_form.html"

    def get_owned_user_alias(self, request: HttpRequest, alias_id: int) -> EmailAlias:
        return get_object_or_404(
            EmailAlias.objects.select_related("domain", "forward_to"),
            pk=alias_id,
            user=request.user,
        )

    def get_owned_mailing_list_alias(self, request: HttpRequest, alias_id: int) -> EmailAlias:
        return get_object_or_404(
            EmailAlias.objects.select_related("domain", "forward_to"),
            pk=alias_id,
            forward_to__owner=request.user,
        )

    def render_form(
        self,
        request: HttpRequest,
        alias: EmailAlias,
        form: MailingListSettingsForm,
        page_title: str,
        status: int = 200,
    ) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "alias": alias,
                "form": form,
                "page_title": page_title,
            },
            status=status,
        )


class EmailAliasConvertToMailingListView(MailingListBaseView):
    def get(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_user_alias(request, alias_id)
        if request.user.delivery_mailbox_id == alias.id:
            messages.error(request, "You cannot convert your primary delivery alias into a mailing list.")
            return redirect("selfservice-dashboard")

        form = MailingListSettingsForm(initial={
            "name": f"{alias.mailprefix}@{alias.domain.name}",
        })
        return self.render_form(request, alias, form, "Convert Alias To Mailing List")

    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_user_alias(request, alias_id)
        if request.user.delivery_mailbox_id == alias.id:
            messages.error(request, "You cannot convert your primary delivery alias into a mailing list.")
            return redirect("selfservice-dashboard")

        form = MailingListSettingsForm(request.POST)
        if not form.is_valid():
            return self.render_form(request, alias, form, "Convert Alias To Mailing List", status=400)

        mailing_list = MailingList(
            name=form.cleaned_data["name"],
            owner=request.user,
            addresses=form.cleaned_data["addresses"],
            new_mailfrom=form.cleaned_data["new_mailfrom"],
        )
        try:
            with transaction.atomic():
                mailing_list.full_clean()
                mailing_list.save()

                alias.user = None
                alias.forward_to = mailing_list
                alias.full_clean()
                alias.save(update_fields=["user", "forward_to"])
        except ValidationError as exc:
            form.add_error(None, exc)
            return self.render_form(request, alias, form, "Convert Alias To Mailing List", status=400)

        messages.success(request, f"Converted {alias.mailprefix}@{alias.domain.name} into a mailing list.")
        return redirect("selfservice-dashboard")


class MailingListEditView(MailingListBaseView):
    def get(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_mailing_list_alias(request, alias_id)
        form = MailingListSettingsForm.from_mailing_list(alias.forward_to)
        return self.render_form(request, alias, form, "Edit Mailing List")

    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_mailing_list_alias(request, alias_id)
        form = MailingListSettingsForm(request.POST)
        if not form.is_valid():
            return self.render_form(request, alias, form, "Edit Mailing List", status=400)

        mailing_list = alias.forward_to
        mailing_list.name = form.cleaned_data["name"]
        mailing_list.addresses = form.cleaned_data["addresses"]
        mailing_list.new_mailfrom = form.cleaned_data["new_mailfrom"]
        mailing_list.owner = request.user
        try:
            mailing_list.full_clean()
            mailing_list.save()
        except ValidationError as exc:
            form.add_error(None, exc)
            return self.render_form(request, alias, form, "Edit Mailing List", status=400)

        messages.success(request, f"Updated mailing list {alias.mailprefix}@{alias.domain.name}.")
        return redirect("selfservice-dashboard")


class MailingListConvertToAliasView(MailingListBaseView):
    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_mailing_list_alias(request, alias_id)
        mailing_list = alias.forward_to
        alias.user = request.user
        alias.forward_to = None
        try:
            alias.full_clean()
            alias.save(update_fields=["user", "forward_to"])
        except ValidationError as exc:
            messages.error(request, "; ".join(exc.messages))
            return redirect("selfservice-dashboard")

        if mailing_list.emailalias_set.exists():
            pass
        else:
            mailing_list.delete()

        messages.success(request, f"Converted {alias.mailprefix}@{alias.domain.name} back to a user alias.")
        return redirect("selfservice-dashboard")


class MailingListDeleteView(MailingListBaseView):
    def post(self, request: HttpRequest, alias_id: int) -> HttpResponse:
        alias = self.get_owned_mailing_list_alias(request, alias_id)
        alias_address = f"{alias.mailprefix}@{alias.domain.name}"
        mailing_list = alias.forward_to
        alias.delete()
        if mailing_list.emailalias_set.exists():
            pass
        else:
            mailing_list.delete()
        messages.success(request, f"Deleted mailing list alias {alias_address}.")
        return redirect("selfservice-dashboard")


class ServiceUserCreateView(SelfServiceAccessMixin, DashboardContextMixin, View):
    def post(self, request: HttpRequest) -> HttpResponse:
        form = ServiceUserCreateForm(request.user, request.POST)
        if form.is_valid():
            service_user = form.save()
            password = form.cleaned_data["password"]
            messages.success(
                request,
                f"Created service user {service_user.username}. Password: {password}",
            )
            return redirect("selfservice-dashboard")
        return self.render_dashboard(request, service_user_form=form, status=400)


class ServiceUserDeleteView(SelfServiceAccessMixin, View):
    def post(self, request: HttpRequest, service_user_id: int) -> HttpResponse:
        service_user = get_object_or_404(MNServiceUser, pk=service_user_id, user=request.user)
        username = service_user.username
        service_user.delete()
        messages.success(request, f"Deleted service user {username}.")
        return redirect("selfservice-dashboard")
