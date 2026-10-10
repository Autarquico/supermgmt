# SuperMgmt M1 node fixture (ADR-0009): Debian + systemd PID 1 + sshd + sudo + docker.
# It has a bootstrap account `admin` with NOPASSWD sudo and NO `supermgmt` user:
# `node.setup` must create that user. Host keys and authorized_keys are injected
# by test/fixtures/fixture at start, so nothing secret is baked into the image.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ENV container=docker DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server sudo docker.io docker-cli \
      iproute2 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*

# The bootstrap human account: key-only login, passwordless sudo, no `supermgmt`.
RUN useradd --create-home --shell /bin/bash admin \
 && usermod -p '*' admin \
 && install -d -m 0700 -o admin -g admin /home/admin/.ssh \
 && printf 'admin ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/admin \
 && chmod 0440 /etc/sudoers.d/admin \
 && visudo -cf /etc/sudoers.d/admin

COPY sshd_fixture.conf /etc/ssh/sshd_config.d/10-fixture.conf
COPY units/ /etc/systemd/system/

# sshd is started by the helper once it has injected the host keys.
RUN systemctl disable ssh.service ssh.socket \
 && systemctl enable docker.service sm-demo.service sm-slow.service \
 && systemctl mask getty.target console-getty.service systemd-logind.service \
      systemd-resolved.service systemd-modules-load.service apt-daily.timer apt-daily-upgrade.timer

STOPSIGNAL SIGRTMIN+3
VOLUME ["/var/lib/docker"]
CMD ["/lib/systemd/systemd"]
