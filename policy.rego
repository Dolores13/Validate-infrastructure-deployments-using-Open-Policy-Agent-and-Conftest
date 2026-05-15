package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.image == "nginx:latest"
    msg := sprintf("Imagen latest no permitida en el contenedor '%v'", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.runAsNonRoot == false
    msg := sprintf("El contenedor '%v' no puede ejecutarse como root", [container.name])
}
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("El contenedor '%v' no tiene límite de memoria definido", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("El contenedor '%v' no tiene límite de CPU definido", [container.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_s3_bucket"
    resource.values.acl == "public-read"
    msg := sprintf("El bucket S3 '%v' es público — solo se permite 'private'", [resource.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_ebs_volume"
    resource.values.encrypted == false
    msg := sprintf("El disco EBS '%v' no está cifrado", [resource.name])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_instance"
    not resource.values.tags
    msg := sprintf("El recurso '%v' no tiene etiquetas obligatorias", [resource.name])
}
