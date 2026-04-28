# SPDX-License-Identifier: Apache-2.0
# Containerfile for pqc-readiness — host-level Post-Quantum Cryptography
# readiness assessment.  Uses Red Hat UBI 10 minimal as the base image.
#
# Build:
#   podman build --format=docker -t pqc-readiness:dev -f Containerfile .
# (The OCI image format does not encode HEALTHCHECK; Docker format does.
#  Drop --format=docker if you do not need the in-image healthcheck —
#  OpenShift uses readiness/liveness probes from the manifest instead.)
#
# Run (host probe — needs host /proc, /sys, /dev, /etc):
#   podman run --rm \
#     --pid=host \
#     -v /proc:/host/proc:ro \
#     -v /sys:/host/sys:ro \
#     -v /dev:/host/dev:ro \
#     -v /etc:/host/etc:ro \
#     pqc-readiness:dev --host-mount /host --json
#
# UBI 10.1 was the current released minor at the time of writing.  Verify
# before bumping:
#   curl -s https://registry.access.redhat.com/v2/ubi10/ubi-minimal/tags/list \
#     | jq '.tags | map(select(test("^10\\.")))'

FROM registry.access.redhat.com/ubi10/ubi-minimal:10.1

LABEL org.opencontainers.image.title="pqc-readiness"
LABEL org.opencontainers.image.description="Host-level PQC readiness assessment"
LABEL org.opencontainers.image.source="https://github.com/aclater/pqc-readiness"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Red Hat (community)"

# microdnf is the only package manager in ubi10-minimal; dnf is not
# available.  --nodocs trims man pages and locales.  openssl pulls in
# the FIPS-validated 3.5.x stack with native ML-KEM / ML-DSA / SLH-DSA
# support.  python3-numpy is required for the STREAM-triad memory-
# bandwidth probe; the script falls back gracefully when missing, but
# every customer report should have a real bandwidth number.
RUN microdnf install -y --nodocs --setopt=install_weak_deps=0 \
        python3 \
        python3-numpy \
        openssl \
        openssh-clients \
    && microdnf clean all \
    && rm -rf /var/cache/yum

# Non-root UID 1001 — required by OpenShift restricted SCC and
# matches the convention in CLAUDE.md.  The probe never writes inside
# the image; outputs are emitted to stdout or a bind-mounted volume.
RUN useradd -r -u 1001 -g 0 -s /sbin/nologin -d /var/lib/pqc-readiness probe \
    && mkdir -p /var/lib/pqc-readiness \
    && chown -R 1001:0 /var/lib/pqc-readiness \
    && chmod -R g+rwX /var/lib/pqc-readiness

COPY --chown=1001:0 pqc_readiness.py /usr/local/bin/pqc-readiness
RUN chmod 0755 /usr/local/bin/pqc-readiness

# Healthcheck: verify the script imports + executes (--help is cheap and
# always exits 0).  ubi10-minimal does not ship curl, so we use python3.
HEALTHCHECK --interval=1h --timeout=5s --start-period=5s --retries=1 \
    CMD python3 /usr/local/bin/pqc-readiness --help >/dev/null 2>&1 || exit 1

USER 1001
WORKDIR /var/lib/pqc-readiness

ENTRYPOINT ["/usr/local/bin/pqc-readiness"]
CMD ["--json"]
