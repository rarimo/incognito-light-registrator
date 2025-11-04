FROM --platform=amd64 golang:1.22.12-alpine as buildbase

ARG CI_JOB_TOKEN

RUN apk add --no-cache git build-base ca-certificates curl bash

WORKDIR /go/src/github.com/rarimo/incognito-light-registrator
COPY . .

RUN git config --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com".insteadOf https://gitlab.com
RUN git config --global url."https://${CI_JOB_TOKEN}@github.com/".insteadOf https://github.com/

RUN go mod tidy && go mod vendor
RUN go build -o /usr/local/bin/incognito-light-registrator


FROM frolvlad/alpine-glibc:alpine-3.22_glibc-2.42

RUN apk add --no-cache libc++ libgcc curl

COPY --from=buildbase /usr/local/bin/incognito-light-registrator /usr/local/bin/incognito-light-registrator
COPY --from=buildbase /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=buildbase /go/src/github.com/rarimo/incognito-light-registrator/verification_keys/* /verification_keys/
COPY --from=buildbase /go/src/github.com/rarimo/incognito-light-registrator/masterList.dev.pem /masterList.dev.pem

ENTRYPOINT ["incognito-light-registrator"]
