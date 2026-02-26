FROM rust:alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY data ./data

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ipapi /app/ipapi
COPY --from=builder /build/data /app/data
COPY build /app/build

EXPOSE 3000

CMD ["/app/ipapi"]
