//! Userspace trace pipeline for eBPF-based build observation.
//!
//! This module implements the userspace side of the mikebom trace pipeline:
//!
//! - **loader**: Loads eBPF bytecode and attaches probes (Linux only)
//! - **processor**: Consumes events from eBPF ring buffers
//! - **aggregator**: (future) Correlates raw events into connections and file operations
//! - **http_parser**: Parses HTTP request/response from TLS plaintext fragments
//! - **sni_extractor**: Extracts SNI hostnames from TLS ClientHello messages
//! - **hasher**: SHA-256 content hashing utilities
//! - **pid_tracker**: Process tree tracking for child PID isolation

pub mod aggregator;
pub mod hasher;
pub mod http_parser;
pub mod loader;
pub mod pid_tracker;
pub mod processor;
pub mod sni_extractor;
