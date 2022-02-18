FROM golang:buster as builder

WORKDIR /workspace
COPY files/llvm-snapshot.gpg.key .

RUN apt-get update && \
    apt-get -y --no-install-recommends install ca-certificates gnupg && \
    apt-key add llvm-snapshot.gpg.key && \
    rm llvm-snapshot.gpg.key && \
    apt-get remove -y gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY files/llvm.list /etc/apt/sources.list.d

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
    make git \
    pkg-config \
    m4 \
    libelf-dev \
    gcc-multilib \
    llvm clang  libbpfcc-dev  libbpf-dev  && \
    rm -rf /var/lib/apt/lists/*


COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
COPY main.go main.go
COPY headers headers
COPY tcp_data.c tcp_data.c
COPY Makefile Makefile

RUN make 

FROM golang:1.16
WORKDIR /
RUN apt-get update && apt-get install iptables -y &&  update-alternatives --set iptables /usr/sbin/iptables-legacy
COPY --from=builder /workspace/app /app
# USER 65532:65532
ENTRYPOINT ["/app"]

EXPOSE 8081