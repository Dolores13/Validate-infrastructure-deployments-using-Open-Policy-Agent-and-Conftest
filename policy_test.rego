package main

import data.main

# Test 1: verifies that the 'latest' image tag is detected and denied
test_image_latest_is_denied if {
    deny["Image 'latest' is not allowed in container 'app'"] with input as {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "app", "image": "nginx:latest"}
                    ]
                }
            }
        }
    }
}

# Test 2: verifies that a properly configured deployment passes all policies
test_image_pinned_version_passes if {
    count(deny) == 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "good-app",
            "labels": {"environment": "development"}
        },
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25.3",
                            "securityContext": {"runAsNonRoot": true},
                            "resources": {
                                "limits": {"memory": "256Mi", "cpu": "500m"}
                            }
                        }
                    ]
                }
            }
        }
    }
}