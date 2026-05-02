FROM golang:1.25 AS builder

COPY . /hstspreload
WORKDIR /hstspreload

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN GOFLAGS=-mod=mod go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN apt update && apt install -y clang

RUN go-fuzz-build -libfuzzer -o mayhem/fuzzParseHeaderString.a github.com/chromium/hstspreload/mayhem && \
    clang -fsanitize=fuzzer mayhem/fuzzParseHeaderString.a -o mayhem/fuzzParseHeaderString.libfuzzer

FROM debian:bookworm-slim
COPY --from=builder /hstspreload/mayhem/fuzzParseHeaderString.libfuzzer /
