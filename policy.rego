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