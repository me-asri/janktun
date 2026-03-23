FROM gcc:14-trixie AS builder

WORKDIR /build
COPY . .

RUN make -j$(nproc) \
    && make strip \
    && make install PREFIX=/opt/janktun

FROM gcr.io/distroless/cc-debian13:latest AS runner

COPY --from=builder /opt/janktun /opt/janktun

ENTRYPOINT [ "/opt/janktun/bin/janktun" ]
