FROM alpine:latest

COPY build/k8s-vault-initializer /

RUN chmod +x /k8s-vault-initializer

ENTRYPOINT ["/k8s-vault-initializer"]
