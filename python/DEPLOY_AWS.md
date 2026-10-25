# Deploying the Python service on an AWS VM (EC2)

This guide takes the Python implementation from an empty AWS account to a running HTTPS endpoint on EC2, then shows how to grow it. Each step lists the commands to run.

It uses the files in this directory: `Dockerfile`, `docker-compose.yml`, `.env.example`, and the shared `../migrations`, `../scripts/db` and `../deploy`.

## Contents

1. [Choose a layout](#1-choose-a-layout)
2. [Size the instance](#2-size-the-instance)
3. [Prerequisites](#3-prerequisites)
4. [Build and push the image to ECR](#4-build-and-push-the-image-to-ecr)
5. [Create the network, IAM role and instance](#5-create-the-network-iam-role-and-instance)
6. [Prepare the VM](#6-prepare-the-vm)
7. [Configure and start](#7-configure-and-start)
8. [Use Amazon RDS instead of the bundled database](#8-use-amazon-rds-instead-of-the-bundled-database)
9. [Secrets from AWS Secrets Manager](#9-secrets-from-aws-secrets-manager)
10. [Logs, metrics and alarms](#10-logs-metrics-and-alarms)
11. [Backups and restore](#11-backups-and-restore)
12. [Upgrades](#12-upgrades)
13. [Scaling out](#13-scaling-out)
14. [Security checklist](#14-security-checklist)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Choose a layout

| Layout | What runs where | Use it for |
|---|---|---|
| **A. Single VM, all in one** | One EC2 instance runs Docker Compose: Caddy (TLS), the app and PostgreSQL. | Staging, small production, proofs of concept. Cheapest. |
| **B. Single VM + RDS** (recommended) | EC2 runs Caddy and the app; the database is Amazon RDS for PostgreSQL (Multi-AZ). | Production. AWS handles database backups, patching and failover. |
| **C. Auto Scaling + ALB + RDS** | An Application Load Balancer (TLS from ACM) in front of an Auto Scaling group of app instances; RDS behind them. | High traffic and zero-downtime deploys. See [§13](#13-scaling-out). |

Sections 3–7 build layout A. [§8](#8-use-amazon-rds-instead-of-the-bundled-database) turns it into B, and [§13](#13-scaling-out) describes C.

```
           Internet
              │ 443/tcp, 443/udp (HTTP/3), 80/tcp (ACME + redirect)
     ┌────────▼─────────────────────── EC2 (Docker Compose) ─┐
     │  Caddy ──► app (uvicorn, N worker processes) ──► db   │  ◄── layout A
     └────────────────────────────────────────────┬──────────┘
                                                  └────► RDS PostgreSQL  ◄── layout B
```

## 2. Size the instance

The service runs **one worker process per vCPU**. Each worker is an asyncio event loop, so a single worker serves thousands of concurrent connections, and the processes together use every core.

| Instance (Graviton, arm64) | vCPU / RAM | Suggested `HTTP_WORKERS` | Notes |
|---|---|---|---|
| `c7g.large` | 2 / 4 GiB | 2 | Good starting point for layout B. |
| `c7g.xlarge` | 4 / 8 GiB | 4 | |
| `m7g.xlarge` | 4 / 16 GiB | 4 | Layout A: leaves memory for PostgreSQL. |
| `c7g.2xlarge` | 8 / 16 GiB | 8 | |

Graviton (arm64) instances give the best price/performance and the image builds natively for them. x86 (`c7i`, `m7i`) works the same; build the image for `linux/amd64` instead.

**Avoid burstable `t4g`/`t3` instances in production.** Login hashes passwords with Argon2id, which is CPU-heavy, and a login burst would drain the CPU credits.

### Settings that depend on the size

- **`HTTP_WORKERS`**: set it to the vCPU count. Inside a container, the CPU count Python sees ignores any CPU limit, so always set it explicitly.
- **`DB_MAX_OPEN_CONNS`** is **per worker**. Total connections are:

  ```
  instances × HTTP_WORKERS × DB_MAX_OPEN_CONNS  (+1 per instance briefly at startup)
  ```

  Keep this below PostgreSQL's `max_connections` with room for admin sessions. For example: 1 instance × 4 workers × 10 = 40.
- **`PASSWORD_HASH_THREADS`** (default 2) is the number of Argon2 hashes each worker runs at once. Each hash holds about 19 MiB while it runs. With 4 workers, peak hashing memory is about 4 × 2 × 19 MiB ≈ 150 MiB.
- **`HTTP_MAX_CONCURRENCY`** (per worker) caps connections plus in-flight requests. Past the cap, the worker answers 503 at once instead of queueing without bound. Leave it at 0 (no cap) until load tests show where latency degrades. Then set it a little below that point.

## 3. Prerequisites

On your workstation:

- **AWS CLI v2**, configured with an IAM principal that can manage EC2, IAM, ECR and (for B) RDS.
- **The Session Manager plugin for the AWS CLI.** It gives shell access without opening SSH.
- **Docker with `buildx`**, to build the image.
- **A DNS name** you control, e.g. `auth.example.com`.

Set these variables once for the commands below:

```sh
export AWS_REGION=eu-west-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export APP=rbac-service-py
export DOMAIN=auth.example.com
```

## 4. Build and push the image to ECR

Build the image in CI or on a workstation, not on the VM. The VM then only pulls a tested, immutable image, and needs neither build tools nor the source code.

```sh
aws ecr create-repository --repository-name $APP \
  --image-scanning-configuration scanOnPush=true \
  --image-tag-mutability IMMUTABLE

export REGISTRY=$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
aws ecr get-login-password | docker login --username AWS --password-stdin $REGISTRY

VERSION=$(git describe --tags --always)
docker buildx build --platform linux/arm64 \
  --build-arg VERSION=$VERSION \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_DATE=$(date -u +%FT%TZ) \
  -t $REGISTRY/$APP:$VERSION --push python/
```

`IMMUTABLE` tags mean a version can never be overwritten. Deploy by version tag, never `latest`.

## 5. Create the network, IAM role and instance

### 5.1 Security group

The instance accepts only web traffic. SSH (port 22) stays closed, because shell access goes through Session Manager.

```sh
VPC_ID=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
SUBNET_ID=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC_ID Name=default-for-az,Values=true \
  --query 'Subnets[0].SubnetId' --output text)

WEB_SG=$(aws ec2 create-security-group --group-name $APP-web --description "rbac-service web" \
  --vpc-id $VPC_ID --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $WEB_SG --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $WEB_SG --protocol udp --port 443 --cidr 0.0.0.0/0   # HTTP/3
aws ec2 authorize-security-group-ingress --group-id $WEB_SG --protocol tcp --port 80  --cidr 0.0.0.0/0   # ACME + redirect
```

For production, use your own VPC with the instance in a public subnet (or behind an ALB, see [§13](#13-scaling-out)) and RDS in private subnets.

### 5.2 IAM role for the instance

The instance needs three permissions:
- **Session Manager:** shell access.
- **ECR read:** pull the image.
- **CloudWatch:** ship logs.

```sh
cat > trust.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
aws iam create-role --role-name $APP-ec2 --assume-role-policy-document file://trust.json
for p in AmazonSSMManagedInstanceCore AmazonEC2ContainerRegistryReadOnly CloudWatchAgentServerPolicy; do
  aws iam attach-role-policy --role-name $APP-ec2 --policy-arn arn:aws:iam::aws:policy/$p
done
aws iam create-instance-profile --instance-profile-name $APP-ec2
aws iam add-role-to-instance-profile --instance-profile-name $APP-ec2 --role-name $APP-ec2
```

### 5.3 Launch the instance

The instance uses the latest Amazon Linux 2023 image for arm64, with:
- an encrypted gp3 root volume
- IMDSv2 required, which blocks SSRF-style theft of the instance credentials
- Docker installed at first boot

```sh
AMI_ID=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 \
  --query Parameter.Value --output text)

cat > user-data.sh <<'EOF'
#!/bin/bash
set -euo pipefail
dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
# High-traffic kernel settings: a deeper accept queue and more local ports.
cat > /etc/sysctl.d/90-rbac.conf <<'SYSCTL'
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 1024 65000
SYSCTL
sysctl --system
EOF

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID --instance-type c7g.large \
  --subnet-id $SUBNET_ID --security-group-ids $WEB_SG \
  --iam-instance-profile Name=$APP-ec2 \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3,Encrypted=true}' \
  --user-data file://user-data.sh \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$APP}]" \
  --query 'Instances[0].InstanceId' --output text)
aws ec2 wait instance-status-ok --instance-ids $INSTANCE_ID
```

### 5.4 Static IP and DNS

```sh
ALLOC_ID=$(aws ec2 allocate-address --domain vpc --query AllocationId --output text)
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $ALLOC_ID
aws ec2 describe-addresses --allocation-ids $ALLOC_ID --query 'Addresses[0].PublicIp' --output text
```

Create an `A` record from `$DOMAIN` to that IP (in Route 53 or your DNS provider) **before** starting the stack. Caddy obtains the TLS certificate on first start, and needs the name to resolve to this instance.

## 6. Prepare the VM

Open a shell. No SSH key or open port is needed:

```sh
aws ssm start-session --target $INSTANCE_ID
sudo -iu ec2-user
docker compose version      # confirms the user-data script finished
```

Put the deployment files on the VM. You need this directory plus the shared `migrations/`, `scripts/db/` and `deploy/` from the repository root.

```sh
git clone https://github.com/MhmdRyhn/gate.git /opt/gate     # or copy a release tarball from S3
cd /opt/gate/python
```

For a private repository, use a read-only deploy key, or have CI upload a tarball to S3 (`aws s3 cp`) that the instance role may read.

## 7. Configure and start

### 7.1 Configuration file

```sh
cp .env.example .env && chmod 600 .env
openssl rand -hex 24      # run twice: POSTGRES_PASSWORD and APP_DB_PASSWORD
vi .env
```

Set at least the following:
- `DOMAIN` and `JWT_ISSUER=https://$DOMAIN`.
- `APP_IMAGE=<registry>/rbac-service-py:<version>`, the tag pushed in [§4](#4-build-and-push-the-image-to-ecr).
- Both database passwords, **also inside** `MIGRATE_DATABASE_URL` and `DATABASE_URL`.
- `HTTP_WORKERS` (the vCPU count) and `DB_MAX_OPEN_CONNS` (see [§2](#2-size-the-instance)).

### 7.2 JWT signing key

The key is generated with the image itself, so no Python is needed on the VM:

```sh
aws ecr get-login-password | docker login --username AWS --password-stdin ${APP_IMAGE%%/*}
mkdir -p secrets && chmod 700 secrets
docker run --rm $APP_IMAGE keys generate > secrets/jwt_signing_key
chmod 444 secrets/jwt_signing_key   # readable by the container's non-root user
```

(Export `APP_IMAGE` in the shell, or substitute the value.) Back up this key, for example in Secrets Manager ([§9](#9-secrets-from-aws-secrets-manager)). If you lose it, every issued token becomes invalid; rotation is described in `../docs/jwt.md`.

### 7.3 Start

```sh
docker compose pull
docker compose up -d --no-build
docker compose ps        # db healthy; migrate and grants exited 0; app healthy; proxy up
docker compose logs -f app
```

Startup runs in this order:
1. PostgreSQL starts.
2. `migrate` applies `../migrations` as the owner role.
3. `grants` gives the application role row access only, and makes the audit log append-only.
4. The app syncs the RBAC registry, then starts `HTTP_WORKERS` worker processes.

### 7.4 First admin and checks

```sh
docker compose run --rm app admin create --email you@example.com      # prompts for the password
curl -s https://$DOMAIN/healthz            # {"status":"ok"}
curl -s https://$DOMAIN/readyz             # {"status":"ok"} once the database is reachable
curl -s https://$DOMAIN/.well-known/jwks.json
```

Make the stack survive reboots: every service has `restart: unless-stopped`, and Docker is enabled by systemd, so nothing else is needed.

## 8. Use Amazon RDS instead of the bundled database

### 8.1 Create the database

```sh
DB_SG=$(aws ec2 create-security-group --group-name $APP-db --description "rbac-service db" \
  --vpc-id $VPC_ID --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $DB_SG --protocol tcp --port 5432 --source-group $WEB_SG

aws rds create-db-instance \
  --db-instance-identifier $APP \
  --engine postgres --engine-version 17 \
  --db-instance-class db.m7g.large \
  --allocated-storage 50 --storage-type gp3 --storage-encrypted \
  --multi-az \
  --master-username rbac_owner --manage-master-user-password \
  --db-name rbac \
  --vpc-security-group-ids $DB_SG \
  --no-publicly-accessible \
  --backup-retention-period 14 \
  --deletion-protection \
  --enable-performance-insights
aws rds wait db-instance-available --db-instance-identifier $APP
aws rds describe-db-instances --db-instance-identifier $APP --query 'DBInstances[0].Endpoint.Address' --output text
```

`--manage-master-user-password` stores the owner password in Secrets Manager. Read it with:

```sh
aws secretsmanager get-secret-value --secret-id <MasterUserSecret ARN> --query SecretString
```

### 8.2 Create the application role (once)

The application connects as a role that can only read and write rows. Create it from the VM:

```sh
docker run --rm -it postgres:17-alpine psql "postgres://rbac_owner:<owner-pw>@<rds-endpoint>:5432/rbac?sslmode=require" \
  -c "CREATE ROLE rbac_app LOGIN PASSWORD '<openssl rand -hex 24>'"
```

### 8.3 Point the stack at RDS

Edit `.env`:

```sh
COMPOSE_PROFILES=                # empty: do not start the bundled db
MIGRATE_DATABASE_URL=postgres://rbac_owner:<owner-pw>@<rds-endpoint>:5432/rbac?sslmode=require
DATABASE_URL=postgres://rbac_app:<app-pw>@<rds-endpoint>:5432/rbac?sslmode=verify-full&sslrootcert=/etc/rds/global-bundle.pem
```

`verify-full` checks the server certificate against the RDS CA. Download the bundle on the VM:

```sh
sudo mkdir -p /etc/rds
sudo curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o /etc/rds/global-bundle.pem
```

Then mount it into the app container. Create `docker-compose.override.yml` next to `docker-compose.yml`; Compose merges it automatically:

```yaml
services:
  app:
    volumes:
      - /etc/rds/global-bundle.pem:/etc/rds/global-bundle.pem:ro
```

Then run `docker compose up -d --no-build`. `migrate` and `grants` run against RDS before the app starts.

### Connection limits

RDS sets `max_connections` from instance memory (`db.m7g.large` allows several hundred).

If you run many instances, put **RDS Proxy** between the app and the database. Then set `DB_STATEMENT_CACHE_SIZE=0`, because prepared statements would pin connections to the proxy.

## 9. Secrets from AWS Secrets Manager

`.env` on disk is fine for one VM. For anything shared or audited, keep the secrets in Secrets Manager and write them to files at boot. The app reads a directory of one-file-per-key with its `dir:` config source.

Store the secrets once:

```sh
aws secretsmanager create-secret --name $APP/prod --secret-string "$(jq -n \
  --arg db 'postgres://rbac_app:...@<rds-endpoint>:5432/rbac?sslmode=verify-full&sslrootcert=/etc/rds/global-bundle.pem' \
  --arg key "$(cat secrets/jwt_signing_key)" \
  '{DATABASE_URL: $db, JWT_SIGNING_KEY: $key}')"
```

Allow the instance role to read only this secret:

```sh
aws iam put-role-policy --role-name $APP-ec2 --policy-name read-app-secret --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"secretsmanager:GetSecretValue\",
    \"Resource\": \"arn:aws:secretsmanager:$AWS_REGION:$ACCOUNT_ID:secret:$APP/prod-*\"}]}"
```

On the VM, write each key to a file before starting the stack. Run it from a systemd unit or the deploy script:

```sh
sudo dnf install -y jq
mkdir -p /opt/gate/python/runtime-secrets && chmod 700 /opt/gate/python/runtime-secrets
aws secretsmanager get-secret-value --secret-id rbac-service-py/prod --query SecretString --output text |
  jq -r 'to_entries[] | @base64' | while read -r e; do
    k=$(echo "$e" | base64 -d | jq -r .key); echo "$e" | base64 -d | jq -r .value \
      > /opt/gate/python/runtime-secrets/$k
  done
chmod 444 /opt/gate/python/runtime-secrets/*
```

Then mount the directory and add it as a config source in `docker-compose.override.yml`. Later sources win, so these values override `.env`:

```yaml
services:
  app:
    volumes:
      - ./runtime-secrets:/run/app-secrets:ro
    command: ["serve", "--config-source", "env", "--config-source", "dir:/run/secrets",
              "--config-source", "dir:/run/app-secrets"]
```

The service can also read configuration straight from **AWS AppConfig** through the AppConfig Agent, using `--config-source http:http://localhost:2772/applications/<app>/environments/<env>/configurations/<profile>`.

## 10. Logs, metrics and alarms

### Logs

The app writes one JSON line per request (method, route template, status, latency, client IP, request ID, user ID), plus application events. URLs with tokens or personal data never reach the logs, because only route templates are logged.

To ship logs to CloudWatch, add the `awslogs` log driver for the app in `docker-compose.override.yml`. The instance role already allows this through `CloudWatchAgentServerPolicy`.

```yaml
services:
  app:
    logging:
      driver: awslogs
      options:
        awslogs-region: eu-west-1
        awslogs-group: /rbac-service-py/app
        awslogs-create-group: "true"
        tag: "{{.Name}}"
```

Useful CloudWatch Logs Insights queries:

```
fields @timestamp, status, route, latency_ms | filter event = "http request" and status >= 500 | sort @timestamp desc
stats pct(latency_ms, 50), pct(latency_ms, 99), count() by route | filter event = "http request"
fields @timestamp, action | filter event = "refresh token reuse detected; session revoked"
```

### Health and alarms

- **Route 53 health check** on `https://$DOMAIN/healthz`, with an alarm that notifies you.
- **EC2 alarms:**
  - `StatusCheckFailed`, with the **recover** action, so AWS moves the instance to healthy hardware.
  - `CPUUtilization` above 70 % for 10 minutes. Argon2 logins are the main CPU consumer.
- **Disk and memory:** install the CloudWatch agent (`dnf install -y amazon-cloudwatch-agent`) for disk and memory metrics. Alarm on the Docker volume filling up.
- **RDS alarms:** `CPUUtilization`, `FreeStorageSpace`, `DatabaseConnections` (close to the budget in [§2](#2-size-the-instance)) and `ReadLatency`.

Create the recovery alarm with:

```sh
aws cloudwatch put-metric-alarm --alarm-name $APP-recover --namespace AWS/EC2 \
  --metric-name StatusCheckFailed_System --dimensions Name=InstanceId,Value=$INSTANCE_ID \
  --statistic Maximum --period 60 --evaluation-periods 2 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:automate:$AWS_REGION:ec2:recover
```

## 11. Backups and restore

**Bundled database (layout A):** `../deploy/backup.sh` writes a `pg_dump` to `./backups` and keeps 14 days. Copy each dump off the instance:

```sh
# crontab -e (as ec2-user)
15 2 * * * cd /opt/gate/python && ../deploy/backup.sh >> backups/backup.log 2>&1 && \
  aws s3 sync backups/ s3://<backup-bucket>/rbac/ --exclude '*' --include 'rbac-*.dump'
```

Give the instance role `s3:PutObject` on that bucket. Use a bucket with versioning and a lifecycle rule that moves old dumps to Glacier.

To restore, run `../deploy/restore.sh backups/<file>.dump`. It stops the app, restores, re-applies grants and starts the app again.

Also enable **EBS snapshots** of the instance volume with Amazon Data Lifecycle Manager, for example daily with 7 days retention.

**RDS (layout B):** automated backups with point-in-time recovery (`--backup-retention-period 14`) are on. Restore to a new instance with `aws rds restore-db-instance-to-point-in-time`, then point `DATABASE_URL` at it.

**The JWT signing key** must be backed up separately (in Secrets Manager); a database backup does not contain it.

## 12. Upgrades

1. Build and push the new version ([§4](#4-build-and-push-the-image-to-ecr)).
2. If it brings a migration, it is applied automatically by the `migrate` service on `up`. Migrations must be backward compatible with the running version (add columns before using them, drop only after no version reads them).
3. Roll out:

   ```sh
   cd /opt/gate/python
   sed -i "s|^APP_IMAGE=.*|APP_IMAGE=$REGISTRY/$APP:<new-version>|" .env
   docker compose pull app && docker compose up -d --no-build
   ```

On a single VM, replacing the container drops in-flight connections for a few seconds. Workers drain for up to `HTTP_SHUTDOWN_TIMEOUT`, and `stop_grace_period` is 30 s. For zero-downtime deploys use layout C.

**Roll back** by setting the previous tag and running the same two commands. Images are immutable, so the old version is exactly what ran before.

## 13. Scaling out

When one instance is not enough, or you need zero-downtime deploys, move to layout C:

```
Route 53 ─► ALB (TLS: ACM certificate, AWS WAF) ─► target group :8080, health check /readyz
                                                       │
                              Auto Scaling group (2+ instances across AZs)
                              each: `docker run` of the app image only (no Caddy, no db)
                                                       │
                                     RDS PostgreSQL Multi-AZ (optionally via RDS Proxy)
```

1. **TLS at the ALB:** request a certificate in ACM and attach it to an HTTPS listener. Caddy is not needed. Redirect HTTP to HTTPS on the ALB.
2. **Launch template:** reuse the user data from [§5.3](#53-launch-the-instance), extended with:
   - an ECR login
   - fetching the secrets ([§9](#9-secrets-from-aws-secrets-manager))
   - starting the app with `docker run -d --restart unless-stopped -p 8080:8080 ... $APP_IMAGE serve --no-sync-rbac ...`

   Run `seed` once per release (from CI or a one-off task) instead of on every instance.
3. **Trusted proxies:** set `HTTP_TRUSTED_PROXIES` to the VPC CIDR, so the client IP comes from the ALB's `X-Forwarded-For`. Allow port 8080 on the instances **only** from the ALB's security group.
4. **Health checks:** use `/readyz` (it checks the database) for the target group, and `/healthz` for the container.
5. **Deregistration delay:** set it to about 30 s, above `HTTP_SHUTDOWN_TIMEOUT`, so instances drain before they stop.
6. **Rolling deploys:** use ASG **instance refresh** with a minimum healthy percentage of 100 %. New instances must pass the health check before old ones are terminated.
7. **Scaling policy:** target tracking on average CPU (around 50 %) or ALB `RequestCountPerTarget`. Recheck the database connection budget ([§2](#2-size-the-instance)) for the maximum group size.
8. **Global rate limiting:** the built-in login rate limiter is per worker process. With several instances, add an **AWS WAF rate-based rule** on the ALB for `/v1/auth/*` (for example, 100 requests per 5 minutes per IP) as the global limit.
9. **Session purge:** run `rbac-service maintenance purge-sessions` on a schedule, as an EventBridge Scheduler → SSM Run Command, and start the instances with `serve --purge-interval 0`.

The service is stateless: sessions live in PostgreSQL and the SSO state lives in a signed cookie. Any instance can serve any request, so no sticky sessions are needed.

## 14. Security checklist

- [ ] No inbound SSH; shell access via Session Manager only. IMDSv2 required.
- [ ] Security groups:
  - Web: 80/443 only.
  - Database: 5432 from the app security group only.
  - Layout C: app port 8080 from the ALB only.
- [ ] Database and EBS volumes encrypted; RDS not publicly accessible; `sslmode=verify-full` for the app.
- [ ] The app connects as `rbac_app` (row access only); the owner role is used by `migrate`/`grants` only.
- [ ] `.env` is mode 600; `secrets/` is mode 700; nothing secret is committed. Prefer Secrets Manager ([§9](#9-secrets-from-aws-secrets-manager)).
- [ ] `APP_ENV=production`: API docs (`/docs`, `/openapi.json`) are disabled.
- [ ] `HTTP_TRUSTED_PROXIES` lists only your proxy or ALB network, so clients cannot spoof their IP.
- [ ] ECR scan-on-push enabled; base image rebuilt regularly for OS patches. Turn on `dnf-automatic` or patch with SSM Patch Manager on the instance.
- [ ] The JWT signing key is backed up, and the rotation procedure in `../docs/jwt.md` has been rehearsed.
- [ ] CloudTrail is on for the account; alarms from [§10](#10-logs-metrics-and-alarms) notify a person.

More threat-model detail is in `../docs/security.md`. It applies to both implementations.

## 15. Troubleshooting

| Symptom | Check |
|---|---|
| `app` restarts and logs `database not reachable` | `docker compose ps db`; for RDS, check the security groups and that `DATABASE_URL` points at the endpoint, not `db`. |
| `grants` fails with `role "rbac_app" does not exist` | On RDS, create the role first ([§8.2](#82-create-the-application-role-once)). |
| Caddy cannot get a certificate | DNS must point at the Elastic IP, and ports 80/443 must be open. Read `docker compose logs proxy`. |
| `ssl` / `certificate verify failed` to RDS | The CA bundle is not mounted, or `sslrootcert` points at the wrong path ([§8.3](#83-point-the-stack-at-rds)). |
| `too many connections` | Lower `DB_MAX_OPEN_CONNS` or `HTTP_WORKERS`, or add RDS Proxy ([§2](#2-size-the-instance)). |
| 503 responses under load, low CPU | `HTTP_MAX_CONCURRENCY` is too low, or the database pool is saturated. Check `DatabaseConnections` and slow-query warnings in the logs. |
| Logins slow under load, CPU at 100 % | Argon2 is CPU-bound by design. Scale out or up; do not lower the hashing cost. |
| All clients share one IP in logs and rate limits | `HTTP_TRUSTED_PROXIES` is not set for your proxy or ALB network. |
| `docker compose run ... admin create` says "no terminal" | `docker compose run` normally allocates a terminal; when piping the password in, use `-T` and `--password-stdin`. |
