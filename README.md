# API Gateway Microservice

Spring Cloud Gateway reverse proxy that routes incoming client traffic to registered microservices.

- **Port**: `8080`
- **Prefix Routes**:
  - `/api/auth/**` $\rightarrow$ `AUTH-SERVICE`
  - `/api/categories/**` $\rightarrow$ `CATEGORY-SERVICE`
  - `/api/expenses/**` $\rightarrow$ `EXPENSE-SERVICE`
  - `/api/reports/**` $\rightarrow$ `REPORT-SERVICE`

### Running
```bash
mvn spring-boot:run
```
