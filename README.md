# AITA - Artificial Intelligence Threat Analyzer

A comprehensive enterprise-grade cybersecurity platform that aggregates, analyzes, and correlates threat intelligence data using advanced AI/ML techniques. AITA provides real-time threat detection, risk assessment, and automated response capabilities.

## 🚀 Features

### Core Capabilities
- **Threat Intelligence Aggregation**: Automated collection from CVE feeds, IP blacklists, malware databases
- **AI-Powered Analysis**: Machine learning models for threat classification and risk scoring
- **NLP Processing**: Advanced text summarization and entity extraction from threat descriptions
- **Real-time Correlation**: Intelligent correlation between security logs and threat intelligence
- **Interactive Dashboard**: Modern React-based web interface with real-time visualizations
- **RESTful API**: Comprehensive FastAPI-based REST API with JWT authentication
- **Automated Alerting**: Smart alert generation based on correlation analysis

### Technical Stack
- **Backend**: Python 3.11+ with FastAPI, SQLAlchemy, Celery
- **Frontend**: React 18+ with TypeScript, Material-UI, D3.js
- **Databases**: PostgreSQL, Redis, Elasticsearch
- **ML/AI**: scikit-learn, PyTorch, Transformers (BART, T5)
- **Infrastructure**: Docker Compose, Nginx, Prometheus, Grafana

## 📋 Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- Node.js 18+ (for frontend development)
- Git

## 🛠 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/lenoshz/aita-threat-analyzer.git
cd aita-threat-analyzer
```

### 2. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env
```

### 3. Start with Docker Compose
```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps
```

### 4. Access the Application
- **Web Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Grafana Monitoring**: http://localhost:3001 (admin/admin)
- **Prometheus Metrics**: http://localhost:9090

### 5. Default Credentials
- **Username**: admin
- **Password**: admin (change immediately after first login)

## 🏗 Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │   Backend API   │
│   (React)       │◄──►│   (Nginx)       │◄──►│   (FastAPI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────┐              │
                       │   Message Queue │◄─────────────┤
                       │   (Redis)       │              │
                       └─────────────────┘              │
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────▼─────────┐
│   Monitoring    │    │   Search Engine │    │   Primary DB      │
│   (Prometheus)  │    │   (Elasticsearch│    │   (PostgreSQL)    │
└─────────────────┘    └─────────────────┘    └───────────────────┘
```

## 📚 API Documentation

### Authentication
```bash
# Register new user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
     -H "Content-Type: application/json" \
     -d '{"username":"user","email":"user@example.com","password":"password123"}'

# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"user","password":"password123"}'
```

### Threat Intelligence
```bash
# Get threats
curl -X GET "http://localhost:8000/api/v1/threats/" \
     -H "Authorization: Bearer YOUR_TOKEN"

# Create new threat
curl -X POST "http://localhost:8000/api/v1/threats/" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"source":"manual","title":"Test Threat","severity":"high"}'
```

## 🧪 Testing

### Run Backend Tests
```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

### Run Frontend Tests
```bash
cd frontend
npm install
npm test
```

### Integration Tests
```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
pytest tests/integration/ -v
```

## 🔧 Development

### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development
```bash
cd frontend
npm install
npm run dev
```

### Database Migrations
```bash
cd backend
alembic upgrade head
```

## 📊 Monitoring

AITA includes comprehensive monitoring and alerting:

- **Application Metrics**: API response times, error rates, throughput
- **Infrastructure Metrics**: CPU, memory, disk usage
- **Business Metrics**: Threat processing rates, correlation accuracy
- **Custom Dashboards**: Grafana dashboards for threat intelligence insights

## 🔐 Security

- **Authentication**: JWT-based with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **API Security**: Rate limiting, input validation, CORS protection
- **Data Protection**: Encrypted secrets, secure headers
- **Network Security**: SSL/TLS encryption, security headers

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/lenoshz/aita-threat-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lenoshz/aita-threat-analyzer/discussions)

## 🙏 Acknowledgments

- NIST National Vulnerability Database for CVE data
- MITRE ATT&CK framework for threat intelligence
- Open source cybersecurity community
- All contributors and users of this project