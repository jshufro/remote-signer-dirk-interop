FROM golang:1.25.1-bookworm AS dependencies 

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

FROM dependencies AS builder

WORKDIR /app

COPY . .

RUN go build -o remote-signer-dirk-interop .

FROM alpine:latest

COPY --from=builder /app/remote-signer-dirk-interop /usr/local/bin/remote-signer-dirk-interop
