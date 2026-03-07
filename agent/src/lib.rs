// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Library crate entry point — exposes agent modules for integration tests
// and benchmarks. The binary entry point is src/main.rs.
#![allow(dead_code, unused_variables, unused_mut)]

pub mod assistant;
pub mod collectors;
pub mod config;
pub mod containment;
pub mod core;
pub mod detection;
pub mod platform_connector;
pub mod voice;
