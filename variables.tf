variable "region" {
  type = string
}

variable "terraform-test-storage-secrets" {
  type      = map(string)
  sensitive = true
}

variable "terraform-test-database-secrets" {
  type      = map(string)
  sensitive = true
}

variable "terraform-test-strapi-secrets" {
  type      = map(string)
  sensitive = true
}
