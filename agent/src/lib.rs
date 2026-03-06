// Copyright 2024 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OpenClaw agent library — exposes internal modules for integration tests and benchmarks.

#![allow(dead_code, unused_variables, unused_mut)]

pub mod assistant;
pub mod collectors;
pub mod config;
pub mod containment;
pub mod core;
pub mod detection;
pub mod platform_connector;
pub mod voice;
