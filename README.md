# Validate Infrastructure Deployments using OPA and Conftest

![CI](https://github.com/Dolores13/Validate-infrastructure-deployments-using-Open-Policy-Agent-and-Conftest/actions/workflows/policy-check.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

This is the practical part of my placement project for my MSc. The topic is about validating infrastructure deployments using Open Policy Agent (OPA) and Conftest.

## What this is about

The idea is to write security policies in a language called Rego that automatically check whether infrastructure configurations follow good security practices. The policies cover both Kubernetes (containers, deployments) and Terraform (S3 buckets, EBS volumes, AWS instances).

For example, the policies check things like: containers not running as root, images not using the "latest" tag (which is bad practice because you never really know which version you're getting), S3 buckets not being public, and production deployments having at least 2 replicas for high availability.

Conftest is the tool that takes the policies and runs them against the configuration files, telling you what passes and what fails.

## What's in here

The project has 8 policies in total:

* 4 Kubernetes policies (no latest image, no root user, memory limits, CPU limits)
* 3 Terraform policies (no public S3, EBS encryption required, mandatory tags)
* 1 high availability policy with two conditions (production environments need 2 or more replicas)

Files in the repo:

* `policy.rego` is where all the security rules live
* `policy_test.rego` has the automated tests for those rules
* `deployment.yaml` is a Kubernetes deployment that breaks rules on purpose, to show Conftest catching them
* `deployment-pass.yaml` is a fixed version that follows the rules
* `terraform-plan.json` is a Terraform plan that also breaks rules on purpose
* `terraform-plan-pass.json` is the clean version
* `.github/workflows/policy-check.yml` is the CI configuration so everything runs automatically on every push

## Tools I used

* OPA v1.16.1
* Conftest v0.68.2
* Rego for writing the policies and the tests
* GitHub Actions for the CI/CD pipeline

## How to run it locally

If you want to try it yourself, the commands are simple.

To check the Kubernetes files:

    conftest test deployment.yaml --policy policy.rego
    conftest test deployment-pass.yaml --policy policy.rego

To check the Terraform plans:

    conftest test terraform-plan.json --policy policy.rego --parser json
    conftest test terraform-plan-pass.json --policy policy.rego --parser json

The "broken" files should fail (that's the point), and the "pass" versions should come back clean.

## Automated tests

I wrote 16 tests for the policies, one fail test and one pass test for each of the 8 policies. They run with OPA itself:

    opa test policy.rego policy_test.rego

You should see PASS: 16/16. The tests verify that the policies work both ways: they catch what they should catch, and they do not complain about things they should not.

## Automation with GitHub Actions

Every time I push to the main branch, GitHub Actions runs the whole pipeline automatically. The robot installs OPA and Conftest in a clean Linux machine, runs the 16 tests, generates a coverage report, and applies the policies against the Kubernetes and Terraform example files.

You can see the latest run by clicking the green badge at the top of this README, or by going to the Actions tab of the repo.

## Notes

The project is licensed under MIT. The Kubernetes and Terraform example files are broken on purpose, and their *-pass versions are clean on purpose. They work as test fixtures for the policies.

