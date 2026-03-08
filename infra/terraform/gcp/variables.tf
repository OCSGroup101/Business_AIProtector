# Copyright 2024 Omni Cyber Solutions LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "omniprotect-prod"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "node_count" {
  description = "Initial node count per zone"
  type        = number
  default     = 2
}

variable "machine_type" {
  description = "GKE node machine type"
  type        = string
  default     = "e2-standard-4"   # 4 vCPU, 16 GB — enough for full stack
}

variable "db_tier" {
  description = "Cloud SQL tier"
  type        = string
  default     = "db-g1-small"   # Upgrade to db-custom-2-7680 for production load
}

variable "static_ip" {
  description = "Reserved static IP for the ingress load balancer"
  type        = string
  default     = "35.201.83.36"
}
