FROM golang:1.21.6-alpine as buildbase

RUN apk add git build-base

WORKDIR /go/src/github.com/rarimo/passport-identity-provider
COPY . .
RUN go mod tidy

RUN GOOS=linux go build  -o /usr/local/bin/incognito-light-registrator /go/src/github.com/rarimo/passport-identity-provider


FROM alpine:3.9

COPY --from=buildbase /usr/local/bin/incognito-light-registrator /usr/local/bin/incognito-light-registrator
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["incognito-light-registrator", "run", "service"]
