FROM golang:1.22-alpine3.19 as builder

RUN apk update && \
    apk add bash jq alpine-sdk sed gawk git ca-certificates curl && \
    apk add --no-cache gcc musl-dev

WORKDIR /go/src/

# get dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy code
COPY . .

# Build project
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /radix-oauth-guard

RUN addgroup -S -g 1000 guard
RUN adduser -S -u 1000 -G guard guard

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /radix-oauth-guard /radix-oauth-guard

EXPOSE 8000
USER 1000
ENTRYPOINT ["/radix-oauth-guard"]
