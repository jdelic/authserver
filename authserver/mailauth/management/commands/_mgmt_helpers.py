import sys
import uuid
from typing import Optional, Tuple

from django.core.exceptions import ValidationError

from mailauth import models


def parse_alias_address(address: str) -> Tuple[str, str]:
    if address.count("@") != 1:
        raise ValueError("Alias must have exactly one '@': %s" % address)
    mailprefix, domain = address.split("@", 1)
    if not mailprefix or not domain:
        raise ValueError("Alias must have both mailprefix and domain: %s" % address)
    return mailprefix, domain


def resolve_domain(domain_name: str) -> models.Domain:
    try:
        return models.Domain.objects.get(name__iexact=domain_name)
    except models.Domain.DoesNotExist as exc:
        raise ValueError("Domain not found: %s" % domain_name) from exc


def resolve_user(user_ref: str) -> models.MNUser:
    try:
        return models.MNUser.objects.resolve_user(user_ref, require_active=False)
    except models.UnresolvableUserException as exc:
        raise ValueError("User not found or unresolvable: %s" % user_ref) from exc


def resolve_mailing_list(list_ref: str) -> models.MailingList:
    try:
        int(list_ref)
    except ValueError:
        qs = models.MailingList.objects.filter(name__iexact=list_ref)
    else:
        qs = models.MailingList.objects.filter(pk=int(list_ref))

    count = qs.count()
    if count == 0:
        raise ValueError("Mailing list not found: %s" % list_ref)
    if count > 1:
        raise ValueError("Mailing list selector is ambiguous: %s" % list_ref)
    return qs.get()


def resolve_service_user(service_user_ref: str) -> models.MNServiceUser:
    try:
        parsed_uuid = uuid.UUID(service_user_ref)
    except ValueError:
        qs = models.MNServiceUser.objects.filter(username=service_user_ref)
    else:
        qs = models.MNServiceUser.objects.filter(pk=parsed_uuid)

    count = qs.count()
    if count == 0:
        raise ValueError("Service user not found: %s" % service_user_ref)
    if count > 1:
        raise ValueError("Service user selector is ambiguous: %s" % service_user_ref)
    return qs.get()


def parse_bool_flag(set_flag: bool, unset_flag: bool, field_name: str) -> Optional[bool]:
    if set_flag and unset_flag:
        raise ValueError("You can't pass both --set-%s and --unset-%s" % (field_name, field_name))
    if set_flag:
        return True
    if unset_flag:
        return False
    return None


def ask_for_confirmation(question: str, default: bool = False) -> bool:
    answer = input("%s " % question).strip().lower()
    if answer == "":
        return default
    while answer not in ["y", "yes", "n", "no"]:
        answer = input("Please answer yes or no: ").strip().lower()
    return answer in ["y", "yes"]


def fail_with_validation_error(prefix: str, exc: ValidationError) -> None:
    if hasattr(exc, "message_dict"):
        sys.stderr.write("%s: %s\n" % (prefix, exc.message_dict))
    else:
        sys.stderr.write("%s: %s\n" % (prefix, str(exc)))
    sys.exit(1)
