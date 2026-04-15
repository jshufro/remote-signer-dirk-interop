PHONY: default
default:
	docker run --rm \
		-v $(PWD)/key_config.yaml:/app/keys/key_config.yaml \
		-v $(PWD)/config.yaml:/app/config.yaml \
		-p 9000:9000 \
		consensys/web3signer:develop \
		--config-file /app/config.yaml \
		eth2 

.PHONY: ci
ci:
	docker run -d --rm \
		--name web3signer-parity \
		-v $(PWD)/key_config.yaml:/app/keys/key_config.yaml \
		-v $(PWD)/config.yaml:/app/config.yaml \
		-p 9000:9000 \
		consensys/web3signer:develop \
		--config-file /app/config.yaml \
		eth2 
	./wait-until-healthy.sh
	go test ./... || (docker logs web3signer-parity && docker stop web3signer-parity && exit 1)
	docker stop web3signer-parity
