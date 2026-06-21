# docker-aurora-serverless

> SQLite-backed MySQL wire protocol proxy — looks like Amazon Aurora Serverless

A docker-iot service that wraps SQLite and exposes it via a MySQL-compatible wire protocol,
making any SQLite database appear as an Amazon Aurora Serverless cluster to MySQL clients.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  docker-aurora-serverless                             │
│                                                       │
│  Port 3306 — MySQL Wire Protocol Proxy (Node.js)      │
│  ┌───────────────────────────────────────────────┐   │
│  │  Speaks MySQL wire protocol (handshake, auth, │   │
│  │  query, result set, OK, ERR, EOF packets)    │   │
│  │  Translates SQL → SQLite queries              │   │
│  └───────────────────┬───────────────────────────┘   │
│                      │                                │
│  ┌───────────────────▼───────────────────────────┐   │
│  │  SQLite databases                              │   │
│  │  /data/<database>.sqlite                       │   │
│  │  NAS volume persisted                          │   │
│  └───────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

## How it works

1. A MySQL client connects to port 3306
2. The proxy speaks the MySQL wire protocol — handles the handshake, authentication, and query/response cycle
3. SQL queries are translated to SQLite and executed against `/data/<database>.sqlite`
4. Result sets are formatted as MySQL wire protocol response packets
5. The client believes it's talking to a real MySQL (Aurora) server

## Supported MySQL Features

| Feature | Support | Notes |
|---------|---------|-------|
| `SELECT` | ✅ | Full SQLite SQL support |
| `INSERT` / `UPDATE` / `DELETE` | ✅ | Standard DML |
| `CREATE DATABASE` | ✅ | Creates `/data/<name>.sqlite` |
| `CREATE TABLE` | ✅ | Standard DDL |
| `ALTER TABLE` | ✅ | SQLite-compatible subset |
| `USE <database>` | ✅ | Switches active SQLite file |
| `SHOW DATABASES` | ✅ | Lists `.sqlite` files in `/data/` |
| `SHOW TABLES` | ✅ | Lists tables in current database |
| Prepared statements | ✅ | Parameterized queries |
| Transactions | ✅ | `BEGIN` / `COMMIT` / `ROLLBACK` |
| Stored procedures | ❌ | SQLite limitation |
| Views | ✅ | Passed through to SQLite |
| Triggers | ✅ | Passed through to SQLite |
| `GRANT` / `REVOKE` | ⚠️ | Accepted, no-op (auth handled at proxy level) |
| `SHOW ENGINE INNODB STATUS` | ⚠️ | Returns stub "AURORA_SERVERLESS" status |

## AWS Compatibility

| AWS Feature | docker-aurora-serverless |
|-------------|------------------------|
| **Port** | 3306 (same) |
| **Wire protocol** | MySQL (same) |
| **Connection string** | `mysql://user:pass@host:3306/db` (same) |
| **Aurora Data API** | Via docker-iot `/api/mobile/sql` (same format) |
| **Engine** | `aurora-mysql` (reported) |
| **EngineMode** | `serverless` (reported) |
| **CloudFormation** | `AWS::RDS::DBCluster` with `EngineMode: serverless` |
| **Scaling** | Single-node (MinCapacity=1, MaxCapacity=1) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AURORA_USER` | `admin` | MySQL username for auth |
| `AURORA_PASSWORD` | `password` | MySQL password for auth |
| `AURORA_PORT` | `3306` | MySQL wire protocol listen port |
| `DATA_DIR` | `/data` | SQLite database directory |
| `DEFAULT_DATABASE` | `aurora` | Default database created on startup |

## CloudFormation (docker-iot)

```yaml
AuroraCluster:
  Type: AWS::RDS::DBCluster
  Properties:
    Engine: aurora-mysql
    EngineMode: serverless
    DatabaseName: myapp
    MasterUsername: admin
    MasterUserPassword: '{{secret:AURORA_PASSWORD}}'
    Port: 3306
    ScalingConfiguration:
      MinCapacity: 1
      MaxCapacity: 1
    StorageEncrypted: true
```

## Docker

### Build
```bash
npm run build:image
```

### Run locally
```bash
docker run -d \
  --name aurora-serverless \
  -p 3306:3306 \
  -v aurora-data:/data \
  -e AURORA_USER=admin \
  -e AURORA_PASSWORD=mysecret \
  gormantec/docker-aurora-serverless:latest
```

### Connect
```bash
mysql -h 127.0.0.1 -P 3306 -u admin -pmysecret aurora
```

## License

MIT
