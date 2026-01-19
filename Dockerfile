FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o main .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/static ./static
COPY --from=builder /app/openapi.json .
COPY --from=builder /app/flag.txt .

EXPOSE 8080
CMD ["./main"]
