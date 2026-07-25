resource "aws_s3_bucket" "public_bucket" {

  bucket = "company-public-bucket"

  acl = "public-read"

}