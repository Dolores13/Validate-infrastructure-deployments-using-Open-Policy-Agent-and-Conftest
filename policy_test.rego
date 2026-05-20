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

# Test 3: verifies that a container running as root is detected and denied
test_root_container_is_denied if {
    deny["Container 'app' cannot run as root"] with input as {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25.3",
                            "securityContext": {"runAsNonRoot": false},
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

# Test 4: verifies that a container with runAsNonRoot=true passes the policy
test_nonroot_container_passes if {
    count(deny) == 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "secure-app",
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

# Test 5: verifies that a container without memory limit is detected and denied
test_missing_memory_limit_is_denied if {
    deny["Container 'app' has no memory limit defined"] with input as {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25.3",
                            "securityContext": {"runAsNonRoot": true},
                            "resources": {
                                "limits": {"cpu": "500m"}
                            }
                        }
                    ]
                }
            }
        }
    }
}

# Test 6: verifies that a container with memory limit defined passes
test_memory_limit_defined_passes if {
    count(deny) == 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "memory-bound-app",
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
                                "limits": {"memory": "512Mi", "cpu": "500m"}
                            }
                        }
                    ]
                }
            }
        }
    }
}

# Test 7: verifies that a container without CPU limit is detected and denied
test_missing_cpu_limit_is_denied if {
    deny["Container 'app' has no CPU limit defined"] with input as {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.25.3",
                            "securityContext": {"runAsNonRoot": true},
                            "resources": {
                                "limits": {"memory": "256Mi"}
                            }
                        }
                    ]
                }
            }
        }
    }
}

# Test 8: verifies that a container with CPU limit defined passes
test_cpu_limit_defined_passes if {
    count(deny) == 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "cpu-bound-app",
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
                                "limits": {"memory": "256Mi", "cpu": "1000m"}
                            }
                        }
                    ]
                }
            }
        }
    }
}

# Test 9: verifies that a public S3 bucket is detected and denied
test_public_s3_bucket_is_denied if {
    count(deny) > 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_s3_bucket",
                        "name": "my-bucket",
                        "values": {"acl": "public-read"}
                    }
                ]
            }
        }
    }
}

# Test 10: verifies that a private S3 bucket passes
test_private_s3_bucket_passes if {
    count(deny) == 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_s3_bucket",
                        "name": "secure-bucket",
                        "values": {"acl": "private"}
                    }
                ]
            }
        }
    }
}

# Test 11: verifies that an unencrypted EBS volume is detected and denied
test_unencrypted_ebs_is_denied if {
    deny["EBS volume 'my-volume' is not encrypted"] with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_ebs_volume",
                        "name": "my-volume",
                        "values": {"encrypted": false}
                    }
                ]
            }
        }
    }
}

# Test 12: verifies that an encrypted EBS volume passes
test_encrypted_ebs_passes if {
    count(deny) == 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_ebs_volume",
                        "name": "secure-volume",
                        "values": {"encrypted": true}
                    }
                ]
            }
        }
    }
}

# Test 13: verifies that an aws_instance without tags is detected and denied
test_missing_tags_is_denied if {
    deny["Resource 'web-server' is missing mandatory tags"] with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_instance",
                        "name": "web-server",
                        "values": {}
                    }
                ]
            }
        }
    }
}

# Test 14: verifies that a tagged aws_instance passes
test_tagged_resource_passes if {
    count(deny) == 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_instance",
                        "name": "tagged-server",
                        "values": {
                            "tags": {
                                "Environment": "production",
                                "Owner": "team-a"
                            }
                        }
                    }
                ]
            }
        }
    }
}

# Test 15: verifies that a production deployment with only 1 replica is detected and denied
test_production_low_replicas_is_denied if {
    count(deny) > 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "critical-app",
            "labels": {"environment": "production"}
        },
        "spec": {
            "replicas": 1,
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

# Test 16: verifies that a production deployment with 2 replicas passes
test_production_two_replicas_passes if {
    count(deny) == 0 with input as {
        "kind": "Deployment",
        "metadata": {
            "name": "ha-app",
            "labels": {"environment": "production"}
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