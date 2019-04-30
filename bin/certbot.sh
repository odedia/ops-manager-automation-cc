#!/bin/bash
sudo certbot --agree-tos -m ${MY_EMAIL} \
  certonly --cert-name  ${DOMAIN}  \
  --dns-google \
  -d "${DOMAIN}, *.${DOMAIN}, *.apps.${DOMAIN}, *.sys.${DOMAIN}, *.login.sys.${DOMAIN}, *.uaa.sys.${DOMAIN}, *.pks.${DOMAIN}" \
  --dns-google-credentials /home/ubuntu/gcp_credentials.json \
  --dns-google-propagation-seconds 60

mkdir -p /home/ubuntu/certs/${DOMAIN}
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem /home/ubuntu/certs/${DOMAIN}/
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem  /home/ubuntu/certs/${DOMAIN}/
