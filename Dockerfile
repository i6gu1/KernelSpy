FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o black-hat .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN apk add --no-cache git

WORKDIR /root/

COPY --from=builder /app/black-hat .
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/i18n ./i18n

RUN mkdir -p uploads

EXPOSE 3000

CMD ["./black-hat"]
