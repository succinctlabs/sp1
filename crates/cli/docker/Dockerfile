FROM ubuntu:24.04@sha256:8a37d68f4f73ebf3d4efafbcf66379bf3728902a8038616808f04e34a9ab63ee

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git dialog xz-utils \
    && curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

ARG BUILDTIME

# Use the BUILDTIME argument to break caching and force a new layer
RUN echo "Cache bust: ${BUILDTIME}" > /dev/null && \
    curl -L https://sp1.succinct.xyz | bash && ~/.sp1/bin/sp1up --c-toolchain

WORKDIR /root/program

ENV CARGO_TERM_COLOR=always
ENTRYPOINT [ "/root/.sp1/bin/cargo-prove" ]
CMD [ "prove" ]