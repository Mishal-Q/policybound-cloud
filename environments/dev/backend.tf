terraform {
  backend "s3" {
    bucket         = "sentinel-iac-tfstate-dev"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "sentinel-iac-tflock-dev"
    encrypt        = true
  }
}
