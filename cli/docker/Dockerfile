FROM ubuntu:24.04@sha256:e3f92abc0967a6c19d0dfa2d55838833e947b9d74edbcb0113e48535ad4be12a

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates clang curl libssl-dev pkg-config git dialog \
    && curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL 'https://sh.rustup.rs' | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN curl -L https://sp1.succinct.xyz | bash && ~/.sp1/bin/sp1up

# Install the C++ toolchain for RISC-V and create a symlink to it in /root/.sp1/bin
RUN mkdir -p /root/.sp1/riscv \
    && curl -L https://github.com/risc0/toolchain/releases/download/2022.03.25/riscv32im-linux-x86_64.tar.xz -o /tmp/riscv32im-linux-x86_64.tar.xz \
    && tar -xvf /tmp/riscv32im-linux-x86_64.tar.xz -C /root/.sp1/riscv/ \
    && rm -f /tmp/riscv32im-linux-x86_64.tar.xz \
    && find /root/.sp1/riscv -name 'riscv32-unknown-elf-gcc' -type f -exec ln -sf {} /root/.sp1/bin/riscv32-unknown-elf-gcc \;

# Add the C++ toolchain to the path and the CC environment variable
ENV PATH="/root/.sp1/bin:${PATH}"
ENV CC_riscv32im_succinct_zkvm_elf=/root/.sp1/bin/riscv32-unknown-elf-gcc

WORKDIR /root/program

ENV CARGO_TERM_COLOR=always
ENTRYPOINT [ "/root/.sp1/bin/cargo-prove" ]
CMD [ "prove" ]