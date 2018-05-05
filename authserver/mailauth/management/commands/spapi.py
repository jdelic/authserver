# -* encoding: utf-8 *-
import argparse

from django.core.management import BaseCommand, CommandParser
from typing import Any

from django.db import connection
from django.db.backends.utils import CursorWrapper


class Command(BaseCommand):
    requires_migrations_checks = True

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

    def _grant(self, **options: Any) -> None:
        cur = connection.cursor()  # type: CursorWrapper
        for user in options["user"]:
            cur.execute("""
                GRANT EXECUTE ON FUNCTION authserver_check_domain(varchar) TO "{username}";
                GRANT EXECUTE ON FUNCTION authserver_get_credentials(varchar) TO "{username}";
                GRANT EXECUTE ON FUNCTION authserver_resolve_alias(varchar, boolean) TO "{username}";
                GRANT EXECUTE ON FUNCTION authserver_iterate_users() TO "{username}";
            """.format(username=user))

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
            "user", nargs="+", action="append", default=[],
            help="The name of the database user to grant access to the stored procedures. 'install' must have been "
                 "called before and the users must already exist"
        )

    def handle(self, *args:Any, **options: Any) -> None:
        if options["scmd"] == "install":
            self._install(**options)
        elif options["scmd"] == "grant":
            self._grant(**options)
        else:
            self.stderr.write("Please specify a command.\n")
            self.stderr.write("Use django-admin.py spapi --settings=authserver.settings --help to get help.\n\n")
