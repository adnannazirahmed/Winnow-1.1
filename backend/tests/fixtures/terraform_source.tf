provider "aws" {
  region = "us-east-1"
}

# Network and storage resources are accepted but outside IAM analysis.
resource "aws_security_group" "bad_sg" {
  name = "insecure-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "insecure-test-bucket-12345"
}

resource "aws_iam_policy" "bad_policy" {
  name = "insecure-admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
