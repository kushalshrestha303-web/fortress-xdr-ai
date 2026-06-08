terraform {
  required_version = ">= 1.7.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }
}

variable "namespace" {
  type    = string
  default = "nepal-fortress-one"
}

resource "kubernetes_namespace" "platform" {
  metadata {
    name = var.namespace
    labels = {
      "istio-injection" = "enabled"
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

