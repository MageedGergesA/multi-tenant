# A throwaway stand-in for ctl-1 (Ubuntu 24.04 with systemd and SSH) for
# infra/test/run.sh: Ansible reaches it over SSH like the real server.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv openssh-server python3 \
        sudo iproute2 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && systemctl enable ssh && mkdir -p /root/.ssh && chmod 700 /root/.ssh \
    && rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
