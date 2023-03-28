# Strelka on Kubernetes

This is a very basic Kubernetes deployment for Strelka that works in Docker Desktop. It may require tuning for various environments. Tested in Kubernetes v1.18.

## How to set up

1. Build the containers. Update image and imagePullPolicy in each deployment if using containers from a registry.
2. Modify the ConfigMap files to suit your needs.
3. Set any resource requests/limits on each of the deployments.
4. Apply the files in the order below.

```#!/bin/bash
kubectl apply -f strelka-namespace.yaml
kubectl apply -f strelka-networkpolicy.yaml
kubectl apply -f yara-pvc.yaml # This will be empty, but could be populated through an initContainer or other method.
kubectl apply -f logs-pvc.yaml
kubectl apply -f gatekeeper-service.yaml
kubectl apply -f gatekeeper-deployment.yaml
kubectl apply -f coordinator-service.yaml
kubectl apply -f coordinator-deployment.yaml
kubectl apply -f manager-configmap.yaml
kubectl apply -f manager-deployment.yaml
kubectl apply -f frontend-configmap.yaml
kubectl apply -f frontend-service.yaml
kubectl apply -f frontend-deployment.yaml
kubectl apply -f backend-configmap.yaml
kubectl apply -f backend-deployment.yaml
```

## To-Do

- Add Envoy proxy example
- Add Horizontal Pod Autoscaler example
