#!/bin/bash
sudo certbot --agree-tos -m ${EMAIL} \
  certonly --cert-name  ${DOMAIN}  \
  --dns-google \
  -d "${DOMAIN}, *.${DOMAIN}, *.apps.${DOMAIN}, *.sys.${DOMAIN}, *.ws.${DOMAIN}, *.login.sys.${DOMAIN}, *.uaa.sys.${DOMAIN}, *.pks.${DOMAIN}" \
  --dns-google-credentials /home/ubuntu/gcp_credentials.json \
  --dns-google-propagation-seconds 60

