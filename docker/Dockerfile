FROM docker.io/golang:1.21 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./
# Download Go module dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Those linker flag enables us to statically link sqlite
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o obligator/obligator .

FROM docker.io/debian:bullseye-slim

WORKDIR /obligator

RUN apt-get update && apt-get install -y ca-certificates

COPY --from=builder /app/obligator /obligator

RUN addgroup --gid 1001 --system appuser && adduser --system --uid 1001 --ingroup appuser appuser
RUN chown -R appuser:appuser /obligator

VOLUME ["/data"]

VOLUME ["/api"]

USER 1001

EXPOSE 1616

ENTRYPOINT ["/obligator/obligator"]

CMD ["-storage-dir", "/data", "-behind-proxy", "true"]
