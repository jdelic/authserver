FROM python:3.6-stretch as target
ADD app /app
ADD appconfig /config
VOLUME /config/authserver
RUN mkdir -p /run/authserver
RUN mkdir -p /usr/share/ca-certificates/local
ADD http://repo.maurus.net/maurusnet-rootca.pem /usr/share/ca-certificates/local/maurusnet-rootca.pem
EXPOSE 8080
CMD ["/app/bin/envdir", "/config/authserver/env", \
     "/app/bin/gunicorn", "-b", "0.0.0.0:8080", \
     "-w", "2", "-p", "/run/authserver/authserver.pid", "--config", \
     "python:authserver.gunicorn_conf", "authserver.wsgi:application"]
