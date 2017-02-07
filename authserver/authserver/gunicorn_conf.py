# -* encoding: utf-8 *-
from gunicorn.workers.base import Worker

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s %(levelname)s %(message)s"
        },
    },
    "handlers": {
        "stdout": {
            "level": "DEBUG",
            "formatter": "simple",
            "class": 'logging.StreamHandler',
            "stream": 'ext://sys.stdout',
        }
    },
    "loggers": {
        "": {
            "handlers": ["stdout"],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}


def post_worker_init(worker: Worker) -> None:
    # We have to fix logging somewhere, why not here.
    import logging
    import logging.config
    from django.conf import settings

    if logging.root:
        del logging.root.handlers[:]

    logging.config.dictConfig(LOGGING)
    logging.debug("start")
