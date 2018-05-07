# -* encoding: utf-8 *-
import argparse

import sys
from django.core.management import BaseCommand, CommandParser
from typing import Any, Sequence

from django.db import connection
from django.db.backends.utils import CursorWrapper


class Command(BaseCommand):
    requires_migrations_checks = True

    spapi_signatures = [
        "authserver_check_domain(varchar)",
        "authserver_resolve_alias(varchar, boolean)",
        "authserver_get_credentials(varchar)",
        "authserver_iterate_users()"
    ]

    def _install(self, **options: Any) -> None:
        cur = connection.cursor()  # type: CursorWrapper
        cur.execute("""
            DROP FUNCTION IF EXISTS authserver_resolve_alias(varchar, boolean);
            CREATE OR REPLACE FUNCTION authserver_resolve_alias(email varchar,
                                                                resolve_to_virtmail boolean DEFAULT FALSE)
                              RETURNS TABLE (alias varchar) AS $$
            DECLARE
                user_mailprefix varchar;
                user_domain varchar;
                primary_email varchar;
                the_alias record;
                the_domain record;
            BEGIN
                SELECT split_part(email, '@', 1) INTO user_mailprefix;
                SELECT split_part(email, '@', 2) INTO user_domain;

                -- handle dashext by resolving it to plusext
                IF position('-' in user_mailprefix) > 0 THEN
                    user_mailprefix := split_part(user_mailprefix, '-', 1) || '+' ||
                                       split_part(user_mailprefix, '-', 2);
                END IF;

                -- handle plusext by cutting it and querying aliases
                IF position('+' in user_mailprefix) > 0 THEN
                    user_mailprefix := split_part(user_mailprefix, '+', 1);
                END IF;

                SELECT domain.* INTO the_domain FROM
                        mailauth_domain AS "domain"
                    WHERE
                        "domain".name=user_domain;

                IF the_domain.redirect_to IS NOT NULL AND the_domain.redirect_to != '' THEN
                    IF resolve_to_virtmail IS TRUE THEN
                        RETURN QUERY SELECT 'virtmail'::varchar;
                        RETURN;
                    ELSE
                        RETURN QUERY SELECT ('@' || the_domain.name)::varchar;
                        RETURN;
                    END IF;
                END IF;

                SELECT alias.* INTO the_alias FROM
                        mailauth_emailalias AS "alias",
                        mailauth_domain AS "domain"
                    WHERE
                        "alias".domain_id="domain".id AND
                        "alias".mailprefix=user_mailprefix AND
                        "domain".name=user_domain;

                -- check for mailing lists (foreign keys to mailauth_mailinglist)
                IF the_alias.forward_to_id IS NOT NULL THEN
                    IF resolve_to_virtmail IS TRUE THEN
                        RETURN QUERY SELECT 'virtmail'::varchar;
                        RETURN;
                    ELSE
                        RETURN QUERY SELECT unnest(addresses) FROM mailauth_mailinglist WHERE
                                        id=the_alias.forward_to_id;
                        RETURN;
                    END IF;
                END IF;

                SELECT primary_alias.mailprefix || '@' || primary_domain.name INTO primary_email FROM
                        mailauth_emailalias AS "alias",
                        mailauth_domain AS "domain",
                        mailauth_emailalias AS "primary_alias",
                        mailauth_domain AS "primary_domain",
                        mailauth_mnuser AS "user"
                    WHERE
                        "primary_alias".user_id="user".uuid AND
                        "primary_domain".id="primary_alias".domain_id AND
                        "user".delivery_mailbox_id="primary_alias".id AND
                        "user".uuid="alias".user_id AND
                        "alias".domain_id="domain".id AND
                        "alias".mailprefix=user_mailprefix AND
                        "domain".name=user_domain AND
                        "user".is_active=TRUE;

                IF primary_email = email AND resolve_to_virtmail IS TRUE THEN
                    RETURN QUERY SELECT 'virtmail'::varchar;  -- primary email aliases are directed to delivery
                    RETURN;
                ELSE
                    IF primary_email IS NULL THEN
                        RETURN;
                    ELSE
                        RETURN QUERY SELECT primary_email;
                        RETURN;
                    END IF;
                END IF;
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER;
        """)
        cur.execute("""
            DROP FUNCTION IF EXISTS authserver_get_credentials(varchar);
            CREATE OR REPLACE FUNCTION authserver_get_credentials(email varchar)
                RETURNS TABLE (username varchar, password varchar, primary_alias varchar) AS $$
            DECLARE
                user_mailprefix varchar;
                user_domain varchar;
                password varchar;
                primary_alias varchar;
            BEGIN
                SELECT split_part(email, '@', 1) INTO user_mailprefix;
                SELECT split_part(email, '@', 2) INTO user_domain;
                SELECT "user".password INTO password FROM
                        mailauth_mnuser AS "user",
                        mailauth_domain AS "domain",
                        mailauth_emailalias AS "alias"
                    WHERE
                        "user".uuid="alias".user_id AND
                        "domain".name=user_domain AND
                        "alias".mailprefix=user_mailprefix AND
                        "alias".domain_id="domain".id;

                SELECT "primary_alias".mailprefix || '@' || "primary_domain".name INTO primary_alias FROM
                        mailauth_mnuser AS "user",
                        mailauth_domain AS "domain",
                        mailauth_domain AS "primary_domain",
                        mailauth_emailalias AS "alias",
                        mailauth_emailalias AS "primary_alias"
                    WHERE
                        "alias".mailprefix=user_mailprefix AND
                        "domain".name=user_domain AND
                        "user".uuid="alias".user_id AND
                        "alias".domain_id="domain".id AND
                        "primary_alias".id="user".delivery_mailbox_id AND
                        "primary_domain".id="primary_alias".domain_id AND
                        "user".is_active=TRUE;

                IF password IS NULL OR password = '' THEN
                    RETURN;
                ELSE
                    RETURN QUERY SELECT email, password, primary_alias;
                    RETURN;
                END IF;
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER;
        """)
        cur.execute("""
            DROP FUNCTION IF EXISTS authserver_check_domain(varchar);
            CREATE OR REPLACE FUNCTION authserver_check_domain(domain varchar) RETURNS varchar AS $$
            DECLARE
                ret varchar;
            BEGIN
                SELECT name INTO ret FROM mailauth_domain WHERE name=domain;
                RETURN ret;
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER;
        """)
        cur.execute("""
            DROP FUNCTION IF EXISTS authserver_iterate_users();
            CREATE OR REPLACE FUNCTION authserver_iterate_users()
                RETURNS TABLE (userid varchar) AS $$
            BEGIN
                RETURN QUERY SELECT ("alias".mailprefix || '@' || "domain".name)::varchar AS userid FROM
                        mailauth_mnuser AS "user",
                        mailauth_domain AS "domain",
                        mailauth_emailalias AS "alias"
                    WHERE
                        "alias".id="user".delivery_mailbox_id AND
                        "domain".id="alias".domain_id AND
                        "user".is_active=TRUE;
                RETURN QUERY SELECT ('@' || "domain".name)::varchar AS userid FROM
                        mailauth_domain AS "domain"
                    WHERE
                        "domain".redirect_to<>'';
                RETURN;
            END;
            $$ LANGUAGE plpgsql SECURITY DEFINER;
        """)

    def _check_install(self, **options: Any) -> None:
        q = ""
        for ix, sig in enumerate(self.spapi_signatures):
            q = "to_regprocedure('{fnsig}') IS NOT NULL AS a{count}{comma}".format(
                    fnsig=sig, count=ix, comma="," if ix < len(self.spapi_signatures) - 1 else "")

        cur = connection.cursor()  # type: CursorWrapper
        cur.execute("""
            SELECT {query}
        """.format(query=q))
        res = cur.fetchone()
        if all(res):
            self.stderr.write(self.style.SUCCESS("SPAPI is installed."))
        else:
            self.stderr.write(self.style.ERROR("SPAPI is NOT installed."))
            sys.exit(1)

    def _check_user(self, user: Sequence[str], **options: Any) -> None:
        q = ""
        for ix, sig in enumerate(self.spapi_signatures):
            q = "has_function_privilege('{user}', '{fnsig}', 'execute') AS a{count}{comma}".format(
                    user=user, fnsig=sig, count=ix, comma="," if ix < len(self.spapi_signatures) - 1 else "")

        cur = connection.cursor()  # type: CursorWrapper
        cur.execute("""
            SELECT {query}
        """.format(query=q))
        res = cur.fetchone()
        if all(res):
            self.stderr.write(self.style.SUCCESS("User {user} has access to the stored procedure API.".format(
                user=user
            )))
        else:
            self.stderr.write(self.style.ERROR("User {user} does NOT have access to the stored procedure API.".format(
                user=user
            )))
            sys.exit(1)

    def _grant(self, user: Sequence[str], **options: Any) -> None:
        cur = connection.cursor()  # type: CursorWrapper
        for u in user:
            for sig in self.spapi_signatures:
                cur.execute("""
                    GRANT EXECUTE ON FUNCTION {fnsignature} TO "{username}";
                """.format(fnsignature=sig, username=u))

    def _revoke(self, user: Sequence[str], **options: Any) -> None:
        cur = connection.cursor()  # type: CursorWrapper
        for u in user:
            for sig in self.spapi_signatures:
                cur.execute("""
                    REVOKE EXECUTE ON FUNCTION {fnsignature} FROM "{username}";
                """.format(fnsignature=sig, username=u))

    def add_arguments(self, parser: CommandParser) -> None:
        cmd = self

        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(cmd, **kwargs)

        subparsers = parser.add_subparsers(
            dest='scmd',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction

        inst_sp = subparsers.add_parser("install", help="Create stored procedure API in the database")
        grant_sp = subparsers.add_parser("grant", help="Grant access to the stored procedure API to a database user")
        grant_sp.add_argument(
            "user", nargs="+",
            help="The names of the database users to grant access to the stored procedures. 'install' must have been "
                 "called before and the users must already have been created in PostgreSQL"
        )
        revoke_sp = subparsers.add_parser("revoke", help="Revoke access to the stored procedure API from a database "
                                                         "user")
        revoke_sp.add_argument("user", nargs="+", action="append", default=[],
                               help="The names of the database users to revoke access from")
        check_sp = subparsers.add_parser("check", help="Check whether the spapi is installed or a user as access")
        check_sp_g = check_sp.add_mutually_exclusive_group(required=True)
        check_sp_g.add_argument("--installed", dest="check_installed", action="store_true", default=False)
        check_sp_g.add_argument("--grant", dest="user", type=str)

    def handle(self, *args:Any, **options: Any) -> None:
        if options["scmd"] == "install":
            self._install(**options)
        elif options["scmd"] == "grant":
            self._grant(**options)
        elif options["scmd"] == "revoke":
            self._revoke(**options)
        elif options["scmd"] == "check":
            if options["check_installed"]:
                self._check_install(**options)
            elif options["user"]:
                self._check_user(**options)
        else:
            self.stderr.write("Please specify a command.\n")
            self.stderr.write("Use django-admin.py spapi --settings=authserver.settings --help to get help.\n\n")
