FROM ubuntu:24.04
# The SSH fixture needs only main; retain Ubuntu's signed updates/security suites.
RUN sed -i 's/^Components:.*/Components: main/' /etc/apt/sources.list.d/ubuntu.sources \
    && printf '%s\n' 'Acquire::Retries "3";' 'Acquire::http::Timeout "20";' 'Acquire::https::Timeout "20";' > /etc/apt/apt.conf.d/80-smoke-network \
    && apt-get update --error-on=any && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home smoke \
    && mkdir -p /run/sshd && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "PasswordAuthentication=yes", "-o", "PermitRootLogin=no"]
