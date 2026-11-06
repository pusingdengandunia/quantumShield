FROM alpine:3.22
RUN apk add --no-cache openssh-server
COPY sshd_config /etc/ssh/sshd_config
# Keys are generated at start so none live in the image layers or the repository.
ENTRYPOINT ["/bin/sh", "-c", "ssh-keygen -q -t ecdsa -N '' -f /etc/ssh/ssh_host_ecdsa_key && exec /usr/sbin/sshd -D -e"]
