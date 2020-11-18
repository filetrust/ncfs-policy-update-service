FROM golang:alpine AS builder
WORKDIR /go/src/github.com/filetrust/ncfs-policy-update-service
COPY . .
RUN cd cmd \
    && env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o  ncfs-policy-update-service .

RUN apk update && \
apk add --no-cache openssl && \
openssl req -x509 -nodes -days 365 -subj "/C=GB/ST=England/O=Glasswall Solutions Ltd/CN=ncfs-policy-update-service.com" -newkey rsa:2048 -keyout /etc/ssl/private/server.key -out /etc/ssl/certs/server.crt;

FROM scratch
COPY --from=builder /go/src/github.com/filetrust/ncfs-policy-update-service/cmd/ncfs-policy-update-service /bin/ncfs-policy-update-service
COPY --from=builder /etc/ssl/private/server.key /etc/ssl/private/
COPY --from=builder /etc/ssl/certs/server.crt /etc/ssl/certs/

ENTRYPOINT ["/bin/ncfs-policy-update-service"]
