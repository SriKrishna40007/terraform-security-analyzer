resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}

resource "aws_s3_bucket_versioning" "logs_versioning" {

  bucket = aws_s3_bucket.logs.id

  versioning_configuration {

    status = "Suspended"

  }

}