FROM --platform=$BUILDPLATFORM golang:1.22-alpine3.19 as builder
# Define target arch variables so we can use them while crosscompiling, will be set automatically
ARG TARGETOS
ARG TARGETARCH
WORKDIR /go/src/

# get dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy code
COPY . .

# Build project
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -ldflags "-s -w" -a -installsuffix cgo -o /radix-oauth-guard


FROM --platform=$TARGETPLATFORM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /radix-oauth-guard /radix-oauth-guard

EXPOSE 8000
USER 1000
ENTRYPOINT ["/radix-oauth-guard"]
