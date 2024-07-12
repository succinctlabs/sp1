FROM ubuntu:24.04@sha256:e3f92abc0967a6c19d0dfa2d55838833e947b9d74edbcb0113e48535ad4be12a

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git dialog
RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl -L https://sp1.succinct.xyz | bash && ~/.sp1/bin/sp1up

# Install RISC-V toolchain
RUN curl -L https://github.com/stnolting/riscv-gcc-prebuilt/releases/download/rv32i-131023/riscv32-unknown-elf.gcc-13.2.0.tar.gz -o /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz \
    && mkdir -p /opt/riscv \
    && tar -xzf /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz -C /opt/riscv/ \
    && rm -f /tmp/riscv32-unknown-elf.gcc-13.2.0.tar.gz

# Set default C compiler and RISC-V toolchain environment variables
ENV PATH="/opt/riscv/bin:${PATH}"
ENV CC=gcc

WORKDIR /root/program

ENV CARGO_TERM_COLOR=always
ENTRYPOINT [ "/root/.sp1/bin/cargo-prove" ]
CMD [ "prove" ]