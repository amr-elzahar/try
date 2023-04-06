# Data
data "aws_partition" "current" {}

data "aws_availability_zones" "available" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "archive_file" "upload_iam_cert" {
    type        = "zip"
    source_file = "upload_iam_cert_function.py"
    output_path = "upload_iam_cert_function.zip"
}

data "archive_file" "call_code_build" {
    type        = "zip"
    source_file = "code_build_function.py"
    output_path ="code_build_function.zip"
}


#  Variables

variable "stack_name" {
  description = "This is resource stack name"
  type = string
  default = "cf-iam-cert"
}

variable "resource_prefix" {
  description = "This is demo resource"
  type = string
  default = "demo"
}

variable "resource_id" {
  description = "ID of the resource"
  type = string
  default = "cloudfront-acm-certificate"
}

variable "lambda_log_level" {
  description = "Lambda Function Logging Level"
  type = string
  default = "DEBUG"
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
  type = string
  default = "10.0.0.0/26"
}

variable "subnet1_cidr_block" {
  description = "CIDR block for subnet 1"
  type = string
  default = "10.0.0.0/28"
}

variable "subnet2_cidr_block" {
  description = "CIDR block for subnet 2"
  type = string
  default = "10.0.16.0/28"
}

variable "alb_name" {
  description = "Name for the application load balancer"
  type = string
  default = "my-alb"
}

variable "acm_certificate_domain_name" {
  description = "Domain name for the ACM certificate"
  type = string
  default = " "
}

#  Provider
terraform {
    required_version = ">= 1.0"

    required_providers {
        aws = {
        source  = "hashicorp/aws"
        version = ">= 4.40"
        }
    }
}

provider "archive" {}

# Create Secret Key to upload certificate to IAM
resource "aws_secretsmanager_secret" "rsa_private_key_secret" {
  name        = "/${var.stack_name}/pk"
  description = "RSA Private Key used to upload certificate to IAM"
}

resource "aws_secretsmanager_secret_version" "rsa_private_key_secret_version" {
  secret_id     = aws_secretsmanager_secret.rsa_private_key_secret.id
  secret_string = "placeholder"
}


resource "aws_ssm_parameter" "rsa_public_key_parameter" {
  name        = "/${var.stack_name}/crt"
  description = "RSA Public Key used to upload certificate to IAM"
  type        = "String"
  value       = "placeholder"
}


resource "aws_codebuild_project" "project" {
  name         = "iam-server-certificate"
  description  = "Create IAM server certificate"
  service_role = aws_iam_role.code_build_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:2.0"

    environment_variable {
      name  = "KEYALGORITHM"
      type  = "PLAINTEXT"
      value = "placeholder"
    }
    environment_variable {
      name  = "SECRETID"
      type  = "PLAINTEXT"
      value = "placeholder"
    }
    environment_variable {
      name  = "PARAMETERNAME"
      type  = "PLAINTEXT"
      value = "placeholder"
    }
    environment_variable {
      name  = "DOMAINNAME"
      type  = "PLAINTEXT"
      value = "placeholder"
    }
    environment_variable {
      name  = "DAYS"
      type  = "PLAINTEXT"
      value = "placeholder"
    }

  }

  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<EOF
      version: 0.2
      phases:
        build:
          commands:
            - openssl req -x509 -sha256 -newkey $KEYALGORITHM -keyout pk.key -out crt.crt -days $DAYS -nodes -subj "/C=US/ST=None/L=None/O=None/CN=$DOMAINNAME"
        post_build:
          commands:
            - aws secretsmanager put-secret-value --secret-id $SECRETID --secret-string file://pk.crt
            - aws ssm put-parameter --name $PARAMETERNAME --value file://pk.crt --overwrite
    EOF
  }
  build_timeout = 8
  # timeouts {
  #   delete = "8m"
  # }
}


#############################
# CodeBuild Lambda Function #
#############################
resource "aws_lambda_function" "call_code_build_function" {
  depends_on = [
    aws_codebuild_project.project
  ]
  filename         = "${data.archive_file.call_code_build.output_path}"
  function_name    = "call_code_build_function"
  role             = aws_iam_role.call_code_build_lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.9"
  timeout          = 600
  source_code_hash = "${data.archive_file.call_code_build.output_base64sha256}"
  environment {
    variables = {
      loglevel = "${var.lambda_log_level}"
    }
  }
}

#############################
#       Lambda Role        #
#############################
# IAM Role for Lambda to call CodeBuild
resource "aws_iam_role" "call_code_build_lambda_role" {

  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  inline_policy {
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ssm:GetParameter"
          ]
          Resource = "${aws_ssm_parameter.rsa_public_key_parameter.arn}"
        },
        {
          Effect = "Allow"
          Action = [
            "codebuild:StartBuild",
            "codebuild:BatchGetBuilds"
          ]
          Resource = "${aws_codebuild_project.project.arn}"
        }
      ]
    })
  }
  managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]
}



#############################
#       CodeBuild Role      #
#############################
# IAM Role for CodeBuild
resource "aws_iam_role" "code_build_role" {
  # Customer-Managed Policy to Allow CodeBuild to call SSM and Secrets Manager
  inline_policy {
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ssm:PutParameter"
          ]
          Resource = "${aws_ssm_parameter.rsa_public_key_parameter.arn}"
        },
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:PutSecretValue"
          ]
          Resource = "${aws_secretsmanager_secret_version.rsa_private_key_secret_version.id}"
        }
      ]
    })
    name = "AddCertValuesPolicy"
  }
  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "codebuild.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]
}



###########################################
#      Upload IAM certificate Function    #
###########################################
resource "aws_lambda_function" "upload_iam_cert_function" {
  function_name    = "upload_iam_cert_function"
  filename         = "${data.archive_file.upload_iam_cert.output_path}"
  source_code_hash = data.archive_file.upload_iam_cert.output_base64sha256
  environment {
    variables = {
      loglevel = var.lambda_log_level
    }
  }
  handler     = "index.my_handler"
  runtime     = "python3.9"
  description = "Custom Resource to Upload IAM Server Certificates."
  memory_size = 128
  timeout     = 120
  role        = aws_iam_role.upload_cert_lambda_role.arn
}


######################################
#      Upload Cert Lambda Role       #
######################################
resource "aws_iam_role" "upload_cert_lambda_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole"
        ]
      }
    ]
  })
  managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]
  inline_policy {
    policy = jsonencode({
      PolicyName = "IAMUploadServerCertificatesGetSecret",
      PolicyDocument = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "IAMServerCertificatesUploadAndDelete"
            Effect = "Allow"
            Action = [
              "iam:DeleteServerCertificate",
              "iam:UploadServerCertificate",
              "iam:GetServerCertificate"
            ]
            Resource = [
              "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:server-certificate/cloudfront/${var.stack_name}*"
            ]
          },
          {
            Sid    = "GetSecret"
            Effect = "Allow"
            Action = [
              "secretsmanager:GetSecretValue"
            ]
            Resource = "${aws_secretsmanager_secret_version.rsa_private_key_secret_version.id}"
          }
        ]
      }
    })
  }
}

#############################################
#     Trigger Codebuild Custom Resource    #
#############################################
resource "aws_cloudformation_stack" "trigger_codebuild_stack" {
  name = "trigger-create-cert"
  parameters = {
    FunctionArn      = aws_lambda_function.call_code_build_function.arn
    BuildProject     = aws_codebuild_project.project.name
    SecretsId        = "/${var.stack_name}/pk"
    RSAParameterName = "/${var.stack_name}/crt"
    ProjectName      = "trigger-codebuild-create-cert"
  }

  template_body = <<STACK
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters" : {
    "FunctionArn" : {
      "Type" : "String",
      "Description" : "Trigger CodeBuild to create certificate"
    },
    "ProjectName" : {
      "Type" : "String",
      "Default" : "trigger-codebuild-create-cert",
      "Description" : "Code Build Project Name"
    }
  },
  "Resources" : {
    "CodeBuildInvocation": {
      "Type" : "AWS::CloudFormation::CustomResource",
      "DeletionPolicy" : "Delete",
      "UpdateReplacePolicy" : "Delete",
      "Properties" : {
        "ServiceToken" : { "Ref" : "FunctionArn" },
        "ProjectName" : { "Ref" : "ProjectName" },
        "KeyAlgorithm": "rsa:2048",
        "SecretId": { "Ref" : "SecretsId" },
        "ParameterName": { "Ref" : "RSAParameterName" },
        "DomainName": "demo-iam-server-cert.com",
        "Days": 3650
      }
    }
  }
}
STACK
}

#############################################
#     Upload IAM Cert Custom Resources      #
#############################################
resource "aws_cloudformation_stack" "upload_iam_cert" {
  name = "UploadCertToIam"
  parameters = {
    FunctionArn      = aws_lambda_function.upload_iam_cert_function.arn,
    SecretsId        = "/${var.stack_name}/pk",
    RSAParameterName = "/${var.stack_name}/crt",
    ServerCertName   = "${var.stack_name}-Certificate",
    ProjectName      = "trigger-upload_iam_cert"
  }

  template_body = <<STACK
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters" : {
    "FunctionArn" : {
      "Type" : "String",
      "Description" : "Trigger CodeBuild to create certificate"
    },
    "ProjectName" : {
      "Type" : "String",
      "Default" : "trigger-upload_iam_cert",
      "Description" : "Code Build Project Name"
    }
  },
  "Resources" : {
    "CodeBuildInvocation": {
      "Type" : "AWS::CloudFormation::CustomResource",
      "DeletionPolicy" : "Delete",
      "UpdateReplacePolicy" : "Delete",
      "Properties" : {
        "ServiceToken" : { "Ref" : "FunctionArn" },
        "CertificateBody": { "Ref" : "RSAParameterName" },
        "CertificateChain": { "Ref" : "RSAParameterName" }, 
        "PrivateKey": { "Ref" : "SecretsId" },
        "ProjectName" : { "Ref" : "ProjectName" },
        "ServerCertificateName": { "Ref" : "ServerCertName" }
      }
    }
  }
}
STACK
}

############################
#       VPC Resources      #
############################

resource "aws_vpc" "vpc" {
  cidr_block = var.vpc_cidr_block
}


resource "aws_subnet" "subnet1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet1_cidr_block
  availability_zone = element(data.aws_availability_zones.available.names, 0)
}



resource "aws_subnet" "subnet2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet2_cidr_block
  availability_zone = element(data.aws_availability_zones.available.names, 1)
}



resource "aws_security_group" "alb_sg" {
  name_prefix = "alb-sg"
  vpc_id      = aws_vpc.vpc.id

   ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_lb" "application_load_balancer" {
  name               = var.alb_name
  internal           = true
  load_balancer_type = "application"
  subnets            = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  security_groups    = [aws_security_group.alb_sg.id]
}


############################
#   CloudFront Resources   #
############################
resource "aws_cloudfront_cache_policy" "cloudfront_cache_policy" {
  name = "${var.resource_prefix}-${var.resource_id}-${data.aws_region.current.name}-cache-policy"

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }

  default_ttl = 3600
  max_ttl     = 86400
  min_ttl     = 60
}



resource "aws_cloudfront_distribution" "cloudfront_distribution_with_certificate" {
  depends_on = [
    aws_cloudfront_cache_policy.cloudfront_cache_policy
  ]

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "origin-id"
    viewer_protocol_policy = "https-only"
    # path_pattern     = "/content/*"
    cache_policy_id        = aws_cloudfront_cache_policy.cloudfront_cache_policy.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    iam_certificate_id       = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:server-certificate/cloudfront/${var.stack_name}*"
    minimum_protocol_version = "TLSv1.2"
    ssl_support_method       = "sni-only"
  }

  origin {
    domain_name = "cloudfront.custom-origin-iam-cert.com"
    origin_id   = "cloudfront-custom-origin-iam-id"
    custom_origin_config {
      origin_protocol_policy = "https-only"
      http_port              = 80
      https_port             = 443
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled = true
  aliases = [var.acm_certificate_domain_name]
  http_version = "http2"

  tags = {
    Name = "cloudfront-custom-origin-iam-cert"
  }
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.cloudfront_distribution_with_certificate.id
}
