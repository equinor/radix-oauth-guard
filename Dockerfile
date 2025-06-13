FROM --platform=$BUILDPLATFORM golang:1.24-alpine3.22 AS builder
# Define target arch variables so we can use them while crosscompiling, will be set automatically
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH} \
    GOOS=${TARGETOS}

WORKDIR /go/src/

# get dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy code
COPY . .

# Build project
RUN go build -ldflags "-s -w" -a -installsuffix cgo -o /radix-oauth-guard

FROM gcr.io/distroless/static

EXPOSE 8000
USER 1000
ENTRYPOINT ["/radix-oauth-guard"]
