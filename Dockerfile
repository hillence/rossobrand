# syntax=docker/dockerfile:1

FROM golang:1.24 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/server main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /app/bin/server /app/server
COPY --from=builder /app/static /app/static
COPY --from=builder /app/templates /app/templates

ENV APP_PORT=8080 PORT=8080
EXPOSE 8080

CMD ["/app/server"]
