#!/bin/bash
(
  pushd tls
  ./gencerts.sh
  popd
) >/dev/null 2>&1
echo "export OCP_TLS_CERT=\$(cat tls/client-cert.pem)"
echo "export OCP_TLS_KEY=\$(cat tls/client-key.pem)"
