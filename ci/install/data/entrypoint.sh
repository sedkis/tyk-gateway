#!/bin/bash

TYKCONF=${TYKCONF:-/opt/tyk-gateway/tyk.conf}

# for backwards compatibility if TYKSECRET is not empty, then set TYK_GW_SECRET to TYKSECRET
if [[ -n "${TYKSECRET}" ]]; then
  export TYK_GW_SECRET="${TYKSECRET}"
fi

# If no TYK_GW_SECRET env set, we will attempt to set it from the "secret" value in tyk.conf
if [[ -z "${TYK_GW_SECRET}" ]]; then
  echo "**************************************************************************************************************"
  echo "*                                           WARNING                                                          *"
  echo "**               USING GATEWAY SECRET IN TYK.CONF BECAUSE NO ENV VARIABLE SET                               **"
  echo "*                                REFER TO IMAGE README FOR MORE INFO                                         *"
  echo "**************************************************************************************************************"
  echo ""
  export TYK_GW_SECRET=$(cat $TYKCONF | jq -r .secret)
fi

# If no secret found in tyk.conf, generate an ephemeral secret for this process.
if [[ -z "${TYK_GW_SECRET}" ]]; then
  export TYK_GW_SECRET=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  echo "WARNING: no gateway secret was configured; generated an ephemeral secret. Set TYK_GW_SECRET explicitly."
fi

cd /opt/tyk-gateway/
./tyk --conf=${TYKCONF}
