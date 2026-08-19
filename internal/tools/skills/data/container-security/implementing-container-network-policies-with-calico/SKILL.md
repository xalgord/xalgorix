---
name: implementing-container-network-policies-with-calico
description: Enforce Kubernetes network segmentation using Calico CNI network policies and global network policies to control
  pod-to-pod traffic, restrict egress, and implement zero-trust microsegmentation.
domain: cybersecurity
subdomain: container-security
tags:
- container-security
- kubernetes
- calico
- network-policy
- microsegmentation
- cni
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---
# Implementing Container Network Policies with Calico

## Overview

Calico provides Kubernetes-native and extended network policy enforcement through its CNI plugin. This skill covers creating and auditing Calico NetworkPolicy and GlobalNetworkPolicy resources to implement pod-to-pod traffic control, namespace isolation, egress restrictions, and DNS-based policy rules using calicoctl and the Kubernetes API.


## When to Use

- When deploying or configuring implementing container network policies with calico capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **No default-deny baseline:** without a deny-all `NetworkPolicy`/`GlobalNetworkPolicy`, Kubernetes defaults to allow-all and your targeted allow rules add nothing. Apply a default-deny per namespace (or a cluster-wide `GlobalNetworkPolicy` with high `order`) first.
- **CNI not actually enforcing:** policies apply cleanly but a non-enforcing dataplane (or Calico not the active CNI) silently no-ops them. Verify: `kubectl exec -n calico-system calicoctl -- calicoctl node status` and confirm pods route through Calico.
- **Calico `order` precedence inverted:** lower `order` numbers win. A permissive Allow at `order: 10` can shadow a Deny at `order: 100`; list with `calicoctl get globalnetworkpolicy -o wide` and check ordering.
- **Egress left open to metadata:** an allow-egress rule that doesn't exclude `169.254.169.254/32` (and Azure `169.254.169.254`) leaves the cloud metadata endpoint reachable for SSRF/credential theft.
- **DNS not allowed before egress deny:** apply the UDP/TCP 53 egress allow or all name resolution breaks, prompting admins to remove the deny entirely.
- **Selector/label typos:** a `selector: app == 'databse'` matches nothing and the policy appears active but protects nothing.
- **Verify enforcement:** `kubectl exec <src> -- wget -qO- --timeout=2 http://<blocked-svc>` must time out, while an allowed path succeeds.

## Prerequisites

- Kubernetes cluster with Calico CNI installed
- Python 3.9+ with `kubernetes` client library
- calicoctl CLI tool installed and configured
- kubectl access with RBAC permissions for network policy management

## Steps

### Step 1: Audit Existing Network Policies
Use calicoctl and kubectl to inventory current network policies and identify unprotected namespaces.

### Step 2: Implement Default-Deny Policies
Create default-deny ingress and egress policies per namespace as a zero-trust baseline.

### Step 3: Create Workload-Specific Allow Rules
Define granular allow rules for legitimate pod-to-pod and pod-to-service communication.

### Step 4: Validate Policy Enforcement
Test connectivity between pods to verify policies are correctly enforced.

## Expected Output

JSON audit report listing all network policies, unprotected namespaces, policy rule counts, and connectivity test results.
