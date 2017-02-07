# -* encoding: utf-8 *-

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s %(levelname)s %(message)s"
        },
    },
    "handlers": {
        "application_logs": {
            "level": "DEBUG",
            "formatter": "simple",
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
            "level": "DEBUG",
            "propagate": True,
        },
        "gunicorn.access": {
            "handlers": ["server_logs"],
            "level": "INFO",
            "propagate": False,
        },
        "gunicorn.error": {
            "handlers": ["application_logs"],
            "level": "INFO",
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
