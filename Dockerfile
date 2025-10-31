FROM docker.io/python:3.11.12-alpine AS constraints

# Install build dependencies
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev

# Copy dependency files first (changes less frequently)
COPY uv.lock pyproject.toml README.rst /tmp/dnsrobocert/

# Generate constraints and build wheel
RUN cd /tmp/dnsrobocert \
 && uv export --no-emit-project --no-hashes > constraints.txt \
 # Remove dns-lexicon constraint since we're using git dependency
 && sed -i '/^dns-lexicon @ git+/d' constraints.txt \
 # Pin OCI to avoid version resolution conflicts and add explicit constraint
 && sed -i 's/oci==.*/oci==2.9.0/' constraints.txt \
 && echo "oci==2.9.0" >> constraints.txt \
 # Pin some packages on armv7l arch to latest available and compatible versions from pipwheels.
 && [ "$(uname -m)" != "armv7l" ] || sed -i 's/cryptography==.*/cryptography==44.0.2/' constraints.txt \
 && [ "$(uname -m)" != "armv7l" ] || sed -i 's/lxml==.*/lxml==5.3.1/' constraints.txt

# Copy source code last (changes most frequently)
COPY src/ /tmp/dnsrobocert/src/

# Install uv and build the wheel
RUN pip install uv \
 && cd /tmp/dnsrobocert \
 && uv build

# Alpine-based final stage for minimal size
FROM docker.io/python:3.11.12-alpine

COPY --from=constraints /tmp/dnsrobocert/constraints.txt /tmp/dnsrobocert/dist/*.whl /tmp/dnsrobocert/

ENV CONFIG_PATH=/etc/dnsrobocert/config.yml
ENV CERTS_PATH=/etc/letsencrypt

# Install only essential runtime dependencies (removed curl, docker-cli as they're not needed for cert operations)
RUN apk add --no-cache \
       git \
       libxslt \
       bash

# Install Python packages with aggressive constraint enforcement
RUN PIP_EXTRA_INDEX_URL=https://www.piwheels.org/simple PIP_CONSTRAINT=/tmp/dnsrobocert/constraints.txt python3 -m pip install --no-cache-dir --no-deps /tmp/dnsrobocert/*.whl \
 # Install all constrained dependencies in one go to avoid resolution conflicts
 && PIP_EXTRA_INDEX_URL=https://www.piwheels.org/simple python3 -m pip install --no-cache-dir \
    acme==5.0.0 certbot==5.0.0 cffi==2.0.0 colorama==0.4.6 coloredlogs==15.0.1 \
    cryptography==46.0.1 dnspython==2.8.0 jsonschema==4.25.1 lxml==6.0.2 \
    pem==23.1.0 pyopenssl==25.3.0 pyyaml==6.0.2 schedule==1.2.2 tldextract==5.3.0 \
    watchdog==4.0.2 \
    oci==2.9.0 \
    "dns-lexicon[full] @ git+https://github.com/jonmeacham/dns-lexicon.git@main" \
 # Create necessary directories
 && mkdir -p /etc/dnsrobocert /etc/letsencrypt \
 # Enhanced cleanup
 && rm -rf /tmp/dnsrobocert /root/.cache /tmp/* /var/tmp/* \
 && find /usr/local -depth \( -type d -a -name test -o -name tests -o -name __pycache__ \) -exec rm -rf '{}' + \
 && find /usr/local -name '*.pyc' -delete \
 && find /usr/local -name "*.pyo" -delete \
 && find /usr/local -name "__pycache__" -type d -exec rm -rf {} + \
 && find /usr/local -name "*.dist-info/WHEEL" -delete \
 && find /usr/local -name "*.dist-info/METADATA" -delete

# For retro-compatibility purpose
RUN mkdir -p /opt/dnsrobocert/bin \
 && ln -s /usr/local/bin/python /opt/dnsrobocert/bin/python

COPY docker/run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]