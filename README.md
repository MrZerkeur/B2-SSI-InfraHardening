## Lynis system hardening :

- Install libpam-tmpdir
https://packages.debian.org/fr/sid/libpam-tmpdir
Secure /tmp

- Install apt-listbugs
https://packages.debian.org/fr/sid/apt-listbugs
List potential bugs when installing a packet, useful to not break the distro

- Install needrestart
https://packages.debian.org/fr/sid/needrestart
Tells you when you need to restart a daemon


## SSH conf hardening

https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-18-04-fr ???

/etc/ssh/sshd_config
```
Include /etc/ssh/sshd_config.d/*.conf

Port 22

PermitRootLogin no
PermitEmptyPasswords no
# PasswordAuthentication no (pas encore de clé)
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM no

X11Forwarding no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
DisableForwarding yes

MaxAuthTries 4
LoginGraceTime 60

AllowUsers axel hugoa

LogLevel VERBOSE

ClientAliveInterval 60
ClientAliveCountMax 3
MaxSessions 10
MaxStartups 10:30:60

KbdInteractiveAuthentication no
PrintMotd no
Subsystem       sftp    /usr/lib/openssh/sftp-server

KexAlgorithms -"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
MACs -"hmac-sha1-etm@openssh.com,hmac-sha1"
HostKeyAlgorithms -"ecdsa-sha2-nistp256"
```

## User account and environment hardening

/etc/login.defs
```
PASS_MAX_DAYS   30   
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
INACTIVE=60
```

/etc/profile
```
TMOUT=600
readonly TMOUT
export TMOUT
```

/etc/profile.d/set_umask.sh
```
umask 027
```

## Least priviledge


## Nginx conf hardening

## AIDE

## Exploit and vuln scan (cf tryhackme room for linux priviledge escalation)