FROM ubuntu:22.04
RUN apt update
RUN echo 1 | apt-get install postfix -y
RUN apt-get install mailutils libsasl2-2 ca-certificates libsasl2-modules -y
COPY main.cf /etc/postfix/main.cf
COPY sasl_passwd /etc/postfix/sasl_passwd
RUN postmap /etc/postfix/sasl_passwd
RUN chmod 400 /etc/postfix/sasl_passwd
RUN chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
RUN chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db