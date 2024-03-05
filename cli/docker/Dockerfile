FROM ubuntu:22.04@sha256:bcc511d82482900604524a8e8d64bf4c53b2461868dac55f4d04d660e61983cb

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git dialog
RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl -L https://sp1.succinct.xyz | bash && ~/.sp1/bin/sp1up

# Hack to fix openssl issue, will not be needed when toolchain is compiled with newer openssl
RUN curl -L http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.21_amd64.deb -o libssl.deb && yes | dpkg -i libssl.deb

WORKDIR /root/program

ENV CARGO_TERM_COLOR=always
ENTRYPOINT [ "/root/.sp1/bin/cargo-prove" ]
CMD [ "prove" ]