#ghcr.io/marcschaeferger/newt-private:1.0.0-otel
#tademsh/newt:1.0.0-otel
FROM golang:1.25-alpine AS builder

# Install git and ca-certificates
RUN apk --no-cache add ca-certificates git tzdata

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Coolify specific Test - set Go proxy to direct to avoid issues
# ENV GOSUMDB=off
ENV GOPROXY=https://goproxy.io,https://proxy.golang.org,direct
RUN go env | grep -E 'GOPROXY|GOSUMDB|GOPRIVATE' && go mod download

# Download all dependencies
#RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /newt

FROM alpine:3.22 AS runner

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /newt /usr/local/bin/
COPY entrypoint.sh /

# Admin/metrics endpoint (Prometheus scrape)
EXPOSE 2112

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["newt"]
