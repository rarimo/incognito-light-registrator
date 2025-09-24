FROM --platform=amd64 golang:1.23.4-alpine as buildbase

ARG CI_JOB_TOKEN

RUN apk add --no-cache git build-base ca-certificates curl bash

WORKDIR /go/src/github.com/rarimo/incognito-light-registrator
COPY . .

RUN git config --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com".insteadOf https://gitlab.com
RUN git config --global url."https://${CI_JOB_TOKEN}@github.com/".insteadOf https://github.com/

RUN go mod tidy && go mod vendor
RUN CGO_ENABLED=1 GO111MODULE=on GOOS=linux go build -o /usr/local/bin/incognito-light-registrator /go/src/github.com/rarimo/incognito-light-registrator

RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash 
RUN /root/.bb/bbup -v 0.66.0
RUN cp /root/.bb/bb /usr/local/bin/bb

RUN which bb
RUN ls -l /usr/local/bin/bb
RUN echo $PATH



FROM --platform=amd64 alpine:3.9


COPY --from=alpine:3.9 /bin/sh /bin/sh
#COPY --from=alpine:3.9 /usr /usr
COPY --from=alpine:3.9 /lib /lib

COPY --from=buildbase /usr/local/bin/bb /usr/local/bin/bb
COPY --from=buildbase /usr/local/bin/incognito-light-registrator /usr/local/bin/incognito-light-registrator
COPY --from=buildbase /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=buildbase /go/src/github.com/rarimo/incognito-light-registrator/verification_keys/* /verification_keys/
COPY --from=buildbase /go/src/github.com/rarimo/incognito-light-registrator/masterList.dev.pem /masterList.dev.pem

ENV PATH="/usr/local/bin:${PATH}"

RUN echo "$(bb -v)"

ENTRYPOINT ["/bin/sh", "-c", "which bb && bb -v && exec incognito-light-registrator"]