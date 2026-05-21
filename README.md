# Validate Infrastructure Deployments using OPA and Conftest



\# Validate Infrastructure Deployments using OPA and Conftest



!\[CI](https://github.com/Dolores13/Validate-infrastructure-deployments-using-Open-Policy-Agent-and-Conftest/actions/workflows/policy-check.yml/badge.svg)

!\[License](https://img.shields.io/badge/license-MIT-blue)



This is the practical part of my placement project for my MSc. The topic is about validating infrastructure deployments using Open Policy Agent (OPA) and Conftest.

## What this is about

The idea is to write security policies in Rego that automatically check whether Kubernetes configurations follow good security practices. For example, making sure containers don't run as root or that images are not using the "latest" tag (which is bad practice because you never really know which version you're getting).

Conftest is the tool that takes the policies and runs them against the configuration files, telling you what passes and what fails.

## What's in here

policy.rego — the security rules I wrote

deployment.yaml — a Kubernetes deployment that breaks the rules on purpose, to show that Conftest can catch the problems

deployment-pass.yaml — a fixed version that follows the rules properly

## Tools I used

OPA v1.16.1

Conftest v0.68.2

Rego for writing the policies

## How to run it

If you want to try it yourself, just run:

conftest test deployment.yaml --policy policy.rego

conftest test deployment-pass.yaml --policy policy.rego

The first one should fail (that's the point) and the second one should pass.

## Notes

This is still a work in progress — I'm adding more policies and a Terraform example as I go.

