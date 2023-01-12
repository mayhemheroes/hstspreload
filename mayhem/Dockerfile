FROM golang:1.18 as builder

COPY . /hstspreload
WORKDIR /hstspreload/mayhem

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN apt update && apt install -y clang


RUN go-fuzz-build -libfuzzer -o fuzzParseHeaderString.a && \
    clang -fsanitize=fuzzer fuzzParseHeaderString.a -o fuzzParseHeaderString.libfuzzer

FROM debian:bookworm-slim
COPY --from=builder /hstspreload/mayhem/fuzzParseHeaderString.libfuzzer /