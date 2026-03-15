PHONY: default
default:
	docker run --rm \
		-v $(PWD)/key_config.yaml:/app/keys/key_config.yaml \
		-v $(PWD)/config.yaml:/app/config.yaml \
		-p 9000:9000 \
		consensys/web3signer:develop \
		--config-file /app/config.yaml \
		eth2 
