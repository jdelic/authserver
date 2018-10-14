FROM python:3.6-stretch as target
ADD app /app
ADD appconfig /etc/appconfig
EXPOSE 8080
CMD ["/app/bin/envdir", "/config/env", "/app/bin/gunicorn", "-b", "127.0.0.1:8080", \
     "-w", "2", "-p", "/run/authserver/authserver.pid", "--config", \
     "python:authserver.gunicorn_conf", "authserver.wsgi:application"]
