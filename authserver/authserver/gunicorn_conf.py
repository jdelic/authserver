# -* encoding: utf-8 *-
import os
from datetime import datetime

from pythonjsonlogger import jsonlogger
from typing import Dict, Any


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record: Dict[str, str], record: Any, message_dict: Dict[str, str]) -> None:
        super().add_fields(log_record, record, message_dict)
        if not log_record.get('appts'):
            # this doesn't use record.created, so it is slightly off
            now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['appts'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname

        if 'exc_info' in log_record and 'exception' not in log_record:
            log_record['exception'] = log_record['exc_info'].split("\n")  # type: ignore
            del log_record['exc_info']


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s %(levelname)s %(message)s",
        },
        "json": {
            '()': 'authserver.gunicorn_conf.CustomJsonFormatter',
            'prefix': '@cee: ',
        }
    },
    "handlers": {
        "application_logs": {
            "level": "DEBUG",
            "formatter": "json",
            "class": 'logging.StreamHandler',
            "stream": 'ext://sys.stderr',
        },
        "server_logs": {
            "level": "INFO",
            "formatter": "simple",
            "class": 'logging.StreamHandler',
            "stream": 'ext://sys.stdout',
        },
    },
    "loggers": {
        "": {
            "handlers": ["application_logs"],
            "level": os.getenv("APPLICATION_LOGLEVEL", "INFO"),
            "propagate": True,
        },
        "gunicorn.access": {
            "handlers": ["server_logs"],
            "level": os.getenv("ACCESSLOG_LOGLEVEL", "INFO"),
            "propagate": False,
        },
        "gunicorn.error": {
            "handlers": ["application_logs"],
            "level": os.getenv("GUNICORN_LOGLEVEL", "ERROR"),
            "propagate": False,
        },
    },
}


# can't add type annotations here, because gunicorn uses 'inspect'
# which chokes on the annotations
def post_worker_init(worker):  # type: ignore
    # We have to fix logging somewhere, why not here.
    import logging
    import logging.config

    if logging.root:
        del logging.root.handlers[:]

    logging.config.dictConfig(LOGGING)
