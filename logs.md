# View Logs in Real-Time (Live Tailing)
# If you want to watch the logs appear live on your screen as requests happen (similar to tail -f), use the -f flag:

# Watch Auth Service logs
kubectl logs -f deployment/auth-service -n default

# Watch User Service logs
kubectl logs -f deployment/user-service -n default

# Watch Notification Service logs
kubectl logs -f deployment/notification-service -n default


# (Press Ctrl + C to stop watching)

# 2. View Past Logs
# If you just want to see the last 100 lines of logs to see what happened recently:

kubectl logs deployment/auth-service --tail=100 -n default

# 3. Download Logs to a File
# If you want to extract the logs so you can download them to your local laptop or search through them in an editor, simply use the > operator to save them to a text file:

# Saves all logs to a file named 'auth-logs.txt' in your current directory
kubectl logs deployment/auth-service -n default > auth-logs.txt

# Saves all logs for the user-service
kubectl logs deployment/user-service -n default > user-logs.txt

# Saves all logs for the notification-service
kubectl logs deployment/notification-service -n default > notification-logs.txt


# Pro-Tip regarding Multiple Replicas: For the auth-service, we configured it to run with 2 Replicas for zero-downtime. If you use deployment/auth-service, Kubernetes will randomly pick one of the two pods to show you the logs for. To guarantee you see the logs aggregated from both active auth pods at the same time, use the label selector -l app=... instead:

kubectl logs -l app=auth-service -n default --tail=200
