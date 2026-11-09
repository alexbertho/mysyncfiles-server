FROM rust:1.98-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release --jobs 1 --bin mysync-server

FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS runtime-deps
COPY --from=build /src/target/release/mysync-server /usr/local/bin/mysync-server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    runtime_root=/runtime; \
    install -D -m 0755 /usr/local/bin/mysync-server "$runtime_root/usr/local/bin/mysync-server"; \
    install -D -m 0755 /usr/bin/tpm2_makecredential "$runtime_root/usr/bin/tpm2_makecredential"; \
    for executable in /usr/local/bin/mysync-server /usr/bin/tpm2_makecredential; do \
        ldd "$executable" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; break } }'; \
    done | sort -u | while IFS= read -r library; do \
        install -D -m 0755 "$library" "$runtime_root$library"; \
    done; \
    install -D -m 0644 /etc/ssl/certs/ca-certificates.crt "$runtime_root/etc/ssl/certs/ca-certificates.crt"; \
    install -D -m 0644 /etc/nsswitch.conf "$runtime_root/etc/nsswitch.conf"; \
    install -d -m 1777 "$runtime_root/tmp"

FROM scratch
COPY --from=runtime-deps /runtime/ /
COPY --chmod=0755 web /web
USER 65532:65532
EXPOSE 8484
ENTRYPOINT ["/usr/local/bin/mysync-server"]
CMD ["serve", "--data-dir", "/data", "--listen", "0.0.0.0:8484", "--web-dir", "/web"]
