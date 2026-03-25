# 1. Build the local docker image
cd /v3/auth-service
docker build -t auth-service:local .

# 2. Import the image into k3s directly 
# (If your k3s uses containerd as runtime)
docker save auth-service:local | sudo k3s ctr images import -

# 3. Apply the updated Deployment
kubectl apply -f /v3/k8s/auth-service-deployment.yaml

# 4. Apply the updated NGINX ConfigMap & Deployment
kubectl apply -f /v3/wss/k8s/nginx-wss.yaml

# 5. Restart NGINX to ensure the proxy rules are active
kubectl rollout restart deployment nginx-wss -n default


# 6. Restart the auth-service to ensure the new image is used
kubectl rollout restart deployment auth-service -n default



