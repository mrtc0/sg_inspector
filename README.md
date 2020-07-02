# noguard sg checker

[![Build Status](https://travis-ci.org/takaishi/sg_inspector.svg?branch=master)](https://travis-ci.org/takaishi/sg_inspector)

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: noguard-sg-checker
  labels:
    app: noguard-sg-checker
spec:
  replicas: 1
  selector:
    matchLabels:
      app: noguard-sg-checker
  template:
    metadata:
      labels:
        app: noguard-sg-checker
    spec:
      containers:
      - name: redis
        image: redis
      - name: noguard-sg-checker-event-watcher
        image: rtakaishi/noguard_sg_checker:latest
        command: ["/sg_inspector", "server", "--config=/path/to/config.toml"]
        volumeMounts:
          - name: noguard-sg-checker-config
            mountPath: /noguard_sg_checker.toml
            subPath: noguard_sg_checker.toml
          - name: noguard-sg-checker-config
            mountPath: policy.rego
            subPath: policy.rego
        env:
          - name: SLACK_TOKEN
            value: XXXXXXXXXXXXX
          - name: SLACK_CHANNEL_NAME
            value: XXXXXXXXXXXXX
      - name: noguard-sg-checker
        image: rtakaishi/noguard_sg_checker:latest
        command: ["/sg_inspector", "cron", "--config=/path/to/config.toml"]
        volumeMounts:
          - name: noguard-sg-checker-config
            mountPath: /noguard_sg_checker.toml
            subPath: noguard_sg_checker.toml
          - name: noguard-sg-checker-config
            mountPath: policy.rego
            subPath: policy.rego
          - name: allow-rules-volume
            mountPath: /conf.d
        env:
          - name: SLACK_TOKEN
            value: XXXXXXXXXXXXX
          - name: SLACK_CHANNEL_NAME
            value: XXXXXXXXXXXXX
          - name: OS_USERNAME
            value: XXXXXXXXXXXXX
          - name: OS_PROJECT_NAME
            value: XXXXXXXXXXXXX
          - name: OS_REGION_NAME
            value: XXXXXXXXXXXXX
          - name: OS_PASSWORD
            value: XXXXXXXXXXXXX
          - name: OS_AUTH_URL
            value: XXXXXXXXXXXXX
      volumes:
      - name: noguard-sg-checker-config
        configMap:
          name: noguard-sg-checker-config
      - name: allow-rules-volume
        configMap:
          name: allow-rules
```
