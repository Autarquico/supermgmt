# SuperMgmt M2 e2e host: a clean Debian with systemd as PID 1 and only what install.sh needs
# (curl, ssh-keygen from openssh-client, ca-certificates), plus zstd to open backup archives in tests.
# No SuperMgmt, no secrets baked in.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ENV container=docker DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus curl ca-certificates openssh-client iproute2 procps zstd \
 && rm -rf /var/lib/apt/lists/*

RUN systemctl mask getty.target console-getty.service systemd-logind.service \
      systemd-resolved.service systemd-modules-load.service apt-daily.timer apt-daily-upgrade.timer

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
