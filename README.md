# Secure Terminal Execution Server

A production-ready, secure and scalable terminal command execution server with OAuth2 authentication, command templates, sandboxed execution, and comprehensive audit logging.

## Features

- **Security First**: OAuth2 authentication, command templates with parameter validation, multi-layered sandboxing
- **Scalable**: Async execution, Redis job queues, horizontal scaling support
- **Auditable**: Comprehensive logging, execution tracking, compliance reporting
- **Production Ready**: Docker containerization, health checks, monitoring

## Architecture

```
API Gateway (FastAPI + OAuth2) → Command Validator → Execution Queue (Redis) → Sandboxed Workers → Audit Logger (PostgreSQL)
```

### Key Components

1. **Command Template Engine**: Parameterized command execution with validation
2. **Multi-layered Security**: OAuth + RBAC + container sandboxing
3. **Async Execution**: Non-blocking command processing with progress tracking
4. **Audit Trail**: Complete execution history and compliance reporting
5. **Monitoring**: Real-time metrics and alerting

## Quick Start

### Prerequisites

- Python 3.9+
- Docker and Docker Compose
- Redis
- PostgreSQL

### Installation

1. Clone the repository:
```bash
git clone https://github.com/luiscnext/secure-terminal-execution-server.git
cd secure-terminal-execution-server
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Start services with Docker Compose:
```bash
docker-compose up -d
```

5. Run database migrations:
```bash
alembic upgrade head
```

6. Start the server:
```bash
python -m src.main
```

## Configuration

### Command Templates

Commands are defined as templates in `config/command_templates.yaml`:

```yaml
templates:
  list_files:
    command: "ls {options} {path}"
    description: "List directory contents"
    parameters:
      path:
        type: "path"
        required: true
        validation: "^/[a-zA-Z0-9_./\\-]*$"
      options:
        type: "string"
        default: "-la"
        allowed_values: ["-la", "-l", "-a"]
    permissions:
      required_scopes: ["file:read"]
      max_execution_time: 30
```

### Security Configuration

- **OAuth2**: Configure in `config/auth.yaml`
- **RBAC**: Role-based access control in `config/permissions.yaml`
- **Sandboxing**: Container security settings in `config/sandbox.yaml`

## API Documentation

Once running, visit `http://localhost:8000/docs` for interactive API documentation.

### Key Endpoints

- `POST /auth/token` - OAuth2 token endpoint
- `GET /commands` - List available command templates
- `POST /execute` - Execute a command
- `GET /jobs/{job_id}` - Get job status
- `GET /audit/logs` - Audit log access

## Security

### Multi-layered Security Model

1. **Authentication**: OAuth2 with JWT tokens
2. **Authorization**: Scope-based permissions per command
3. **Input Validation**: Parameter validation against schemas
4. **Sandboxing**: Docker containers with resource limits
5. **Monitoring**: Real-time anomaly detection
6. **Audit**: Complete execution tracking

### Deployment Security

- Use HTTPS in production
- Rotate JWT signing keys regularly
- Monitor for unusual command patterns
- Implement network segmentation
- Regular security scanning

## Monitoring and Observability

- **Metrics**: Prometheus metrics at `/metrics`
- **Health Checks**: `/health` endpoint
- **Logging**: Structured JSON logging
- **Tracing**: OpenTelemetry integration

## Testing

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Security tests
pytest tests/security/

# Load tests
locust -f tests/load/locustfile.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure security tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

For security issues, please email security@example.com instead of using the issue tracker.
