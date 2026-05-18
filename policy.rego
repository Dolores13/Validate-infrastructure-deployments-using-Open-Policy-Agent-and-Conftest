package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.image == "nginx:latest"
    msg := sprintf("Image 'latest' is not allowed in container '%v'", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.runAsNonRoot == false
    msg := sprintf("Container '%v' cannot run as root", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' has no memory limit defined", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%v' has no CPU limit defined", [container.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_s3_bucket"
    resource.values.acl == "public-read"
    msg := sprintf("S3 bucket '%v' is public — only 'private' is allowed", [resource.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_ebs_volume"
    resource.values.encrypted == false
    msg := sprintf("EBS volume '%v' is not encrypted", [resource.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_instance"
    not resource.values.tags
    msg := sprintf("Resource '%v' is missing mandatory tags", [resource.name])
}

deny contains msg if {
    input.kind == "Deployment"
    input.metadata.labels.environment == "production"
    input.spec.replicas < 2
    msg := sprintf("Deployment '%v' is in production with only %v replica(s) — minimum 2 required for high availability", [input.metadata.name, input.spec.replicas])
}

   
