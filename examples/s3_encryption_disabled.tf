resource "aws_s3_bucket" "secure_bucket" {

  bucket = "company-data"

}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {

  bucket = aws_s3_bucket.secure_bucket.id

}