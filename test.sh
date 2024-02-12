cargo test --package curta-core --lib --release -- operations::field::fp_sqrt::tests --nocapture && \
    cargo test --package curta-core --lib --release -- operations::field::fp_op::tests --nocapture && \
    cargo test --package curta-core --lib --release -- operations::field::fp_op::tests --nocapture && \
    cargo test --package curta-core --lib --release -- operations::field::fp_inner_product::tests --nocapture && \
    cargo test --package curta-core --lib --release -- operations::field::fp_den::tests --nocapture 
