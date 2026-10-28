# Odoo 19.0 Community image for the DOC-06 benchmark (ADR-H0-010 cell:
# Ubuntu 24.04, Python 3.12). Built from a pinned upstream commit, never
# from a working tree (ADR-H0-019 provenance rule).
FROM ubuntu:24.04

ARG ODOO_COMMIT
ARG WKHTMLTOX_URL=https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.jammy_amd64.deb
ARG WKHTMLTOX_SHA256

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl python3 python3-venv python3-dev build-essential \
        libpq-dev libldap2-dev libsasl2-dev libxml2-dev libxslt1-dev \
        libjpeg-dev zlib1g-dev libffi-dev postgresql-client \
        fonts-noto-core fonts-noto-cjk fontconfig xfonts-75dpi xfonts-base \
    && curl -fsSL -o /tmp/wkhtmltox.deb "$WKHTMLTOX_URL" \
    && if [ -n "$WKHTMLTOX_SHA256" ]; then echo "$WKHTMLTOX_SHA256  /tmp/wkhtmltox.deb" | sha256sum -c -; fi \
    && apt-get install -y --no-install-recommends /tmp/wkhtmltox.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/wkhtmltox.deb

RUN test -n "$ODOO_COMMIT" \
    && mkdir -p /opt/odoo \
    && curl -fsSL "https://github.com/odoo/odoo/archive/${ODOO_COMMIT}.tar.gz" \
       | tar -xz --strip-components=1 -C /opt/odoo

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/odoo/requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir -e /opt/odoo --no-deps

# DOC-04 §5.4 platform_defaults one-shot (fixed script, scope is the only argument).
COPY platform/ /opt/platform/

# Arbitrary-UID friendly (ADR-H0-011): nothing writable outside /var/lib/odoo.
RUN mkdir -p /var/lib/odoo && chmod 1777 /var/lib/odoo
ENV PATH=/opt/venv/bin:$PATH ODOO_RC=/etc/odoo/odoo.conf
LABEL org.teklines.odoo.commit=$ODOO_COMMIT
USER 1000
EXPOSE 8069 8072
ENTRYPOINT ["odoo"]
