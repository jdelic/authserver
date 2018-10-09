FROM python:3.6-stretch as buildsystem-base
WORKDIR /authserver
RUN apt-get --no-install-recommends -q -y -o DPkg::Options::=--force-confold \
        -o DPkg::Options::=--force-confdef install \
        build-essential python3 python3-virtualenv virtualenv python3-pip \
        libssl-dev libffi-dev libpq-dev python3-dev


FROM buildsystem-base as builder
WORKDIR /authserver
RUN virtualenv /app && /app/bin/pip install /authserver


FROM python:3.6-stretch as target
COPY --from=builder /app /app
EXPOSE 8080
CMD ['/app/bin/envdir', '/config/env', '/app/bin/gunicorn', '-b', '127.0.0.1:8080', \
     '-w', '2', '-p', '/run/authserver/authserver.pid', '--config', \
     'python:authserver.gunicorn_conf', 'authserver.wsgi:application']
