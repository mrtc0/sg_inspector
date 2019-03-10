FROM golang:latest as build

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH
ENV CGO_ENABLED 0
ENV GO111MODULE on

RUN mkdir -p /go/{src,bin,pkg}

ADD . /go/src/github.com/takaishi/noguard_sg_checker
WORKDIR /go/src/github.com/takaishi/noguard_sg_checker
RUN go get
RUN go build

FROM alpine:3.8 as app
RUN apk --no-cache add ca-certificates
WORKDIR /
COPY --from=build /go/src/github.com/takaishi/noguard_sg_checker/noguard_sg_checker /noguard_sg_checker

ENTRYPOINT ["/noguard_sg_checker", "server", "--config", "/config.toml"]
