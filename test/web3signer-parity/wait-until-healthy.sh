#!/bin/bash

MAX_RETRIES=30
RETRIES=0
SLEEP_INTERVAL=1
while ! curl -f http://localhost:9000/api/v1/eth2/publicKeys | grep 0xab0b; do
	sleep $SLEEP_INTERVAL
	RETRIES=$((RETRIES + 1))
	if [ $RETRIES -ge $MAX_RETRIES ]; then
		echo "Web3Signer is not healthy after $MAX_RETRIES retries"
		exit 1
	fi
	echo "Web3Signer is not healthy, retrying... ($RETRIES/$MAX_RETRIES)"
done

echo "Web3Signer is healthy"
