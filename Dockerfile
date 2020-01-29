FROM golang:latest as build

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH
ENV CGO_ENABLED 0
ENV GO111MODULE on

RUN mkdir -p /go/{src,bin,pkg}

ADD . /go/src/github.com/takaishi/sg_inspector
WORKDIR /go/src/github.com/takaishi/sg_inspector
RUN go get
RUN go build

FROM alpine:3.8 as app
RUN apk --no-cache add ca-certificates
WORKDIR /
COPY --from=build /go/src/github.com/takaishi/sg_inspector/sg_inspector /sg_inspector

ENTRYPOINT ["/sg_inspector", "server", "--config", "/config.toml"]
