# Aligned Borrow Derive

This crate provides a set of procedural macros designed to simplify the implementation of traits related to aligned borrowing and machine air functionalities in Rust. These macros are particularly useful for projects involving complex data structures and machine learning models, where memory alignment and efficient trait implementations are crucial.

## Features

- **Aligned Borrow Derive**: 
  - Implements the `Borrow` and `BorrowMut` traits for types with generics.
  - Ensures correct and safe memory alignment.
  - Supports complex generic types, including type and const generics.

- **Machine Air Derive**: 
  - Provides a comprehensive implementation of the `MachineAir` trait for enums.
  - Supports operations such as trace generation, dependency management, and evaluation.
  - Automatically handles complex enum variants with single fields.

- **Cycle Tracker**: 
  - A procedural macro attribute to track the execution cycles of functions.
  - Useful for performance analysis and debugging.
  - Outputs start and end cycle information to standard error.

- **Cycle Tracker Recursion**: 
  - Similar to `Cycle Tracker`, but specifically designed for recursive functions.
  - Integrates with `CircuitV2Builder` for enhanced tracking capabilities.

