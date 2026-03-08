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

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
  }

  backend "gcs" {
    bucket = "omniprotect-prod-tfstate"
    prefix = "gke/prod"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "google_compute_network" "main" {
  name                    = "omniprotect-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke" {
  name          = "omniprotect-gke"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.main.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.16.0.0/14"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.20.0.0/20"
  }

  private_ip_google_access = true
}

# ── GKE Cluster ───────────────────────────────────────────────────────────────

resource "google_container_cluster" "main" {
  name     = "omniprotect-prod"
  location = var.region

  # Use separate node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.gke.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  deletion_protection = false
}

resource "google_container_node_pool" "main" {
  name       = "omniprotect-nodes"
  cluster    = google_container_cluster.main.id
  node_count = var.node_count

  autoscaling {
    min_node_count = 2
    max_node_count = 10
  }

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 50
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# ── Cloud SQL (PostgreSQL 16) ─────────────────────────────────────────────────

resource "google_sql_database_instance" "main" {
  name             = "omniprotect-pg"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"   # HA with failover replica

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      backup_retention_settings {
        retained_backups = 14
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
      require_ssl     = true
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }
  }

  deletion_protection = true
}

resource "google_sql_database" "omniprotect" {
  name     = "omniprotect"
  instance = google_sql_database_instance.main.name
}

# ── Memorystore (Redis 7) ─────────────────────────────────────────────────────

resource "google_redis_instance" "main" {
  name           = "omniprotect-redis"
  tier           = "STANDARD_HA"
  memory_size_gb = 2
  region         = var.region

  authorized_network = google_compute_network.main.id

  redis_version     = "REDIS_7_0"
  display_name      = "OmniProtect Redis"
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}

# ── Cloud DNS ─────────────────────────────────────────────────────────────────

data "google_dns_managed_zone" "omnicybersolutions" {
  name = "omnicybersolutions-com"
}

resource "google_dns_record_set" "omniprotect" {
  name         = "omniprotect.omnicybersolutions.com."
  type         = "A"
  ttl          = 300
  managed_zone = data.google_dns_managed_zone.omnicybersolutions.name
  rrdatas      = [var.static_ip]
}

# ── Terraform state bucket ───────────────────────────────────────────────────

resource "google_storage_bucket" "tfstate" {
  name          = "omniprotect-prod-tfstate"
  location      = var.region
  force_destroy = false

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true
}
