#!/bin/sh
# Starts a throwaway OpenSSH server in Docker for the integration tests.
#   user: tester  password: testpass123  port: 127.0.0.1:2222
# Public keys from SSHMobileTests/Fixtures/*.pub are authorized (passphrase for *_enc keys: "secret").
set -e
cd "$(dirname "$0")/.."
KEYS=$(cat SSHMobileTests/Fixtures/*.pub)
docker rm -f sshmobile-test >/dev/null 2>&1 || true
docker run -d --name sshmobile-test -p 127.0.0.1:2222:22 -e AUTHORIZED_KEYS="$KEYS" alpine:3.20 sh -c '
set -e
apk add --no-cache openssh >/dev/null
ssh-keygen -A
adduser -D tester
echo "tester:testpass123" | chpasswd
mkdir -p /home/tester/.ssh
printf "%s\n" "$AUTHORIZED_KEYS" > /home/tester/.ssh/authorized_keys
chown -R tester /home/tester/.ssh && chmod 700 /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys
sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/; s/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/; s/^#\?GatewayPorts.*/GatewayPorts yes/; s/^#\?PermitUserEnvironment.*/PermitUserEnvironment yes/" /etc/ssh/sshd_config
echo "AcceptEnv *" >> /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e'
echo "waiting for sshd..."
for i in $(seq 1 30); do
  if (echo | nc -w1 127.0.0.1 2222 2>/dev/null | grep -q SSH-2.0); then echo "ready on 127.0.0.1:2222"; exit 0; fi
  sleep 1
done
echo "server did not come up"; docker logs sshmobile-test; exit 1
