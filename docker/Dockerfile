FROM docker.io/golang:1.21 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./
# Download Go module dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Those linker flags statically link sqlite.
# Check out https://www.arp242.net/static-go.html to understand these build parameters.
RUN CGO_ENABLED=1 GOOS=linux go build \
  -a \
  -ldflags '-linkmode external -extldflags "-static"' \
  -tags sqlite_omit_load_extension,netgo \
  -o obligator/obligator .

FROM docker.io/alpine:3.18

WORKDIR /obligator

RUN apk --no-cache add ca-certificates && \
    addgroup -S appuser -g 1001 && \
    adduser -S -G appuser -u 1001 appuser

COPY --from=builder /app/obligator /obligator

RUN chown -R appuser:appuser /obligator

VOLUME ["/data"]

VOLUME ["/api"]

USER 1001

EXPOSE 1616

ENTRYPOINT ["/obligator/obligator"]

CMD ["-storage-dir", "/data", "-behind-proxy", "true"]
