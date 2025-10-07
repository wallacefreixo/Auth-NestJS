# Backend NestJS – Autenticação com JWT, Cookies HTTP-only, Redis e Segurança

## 🛠 Tecnologias utilizadas

- NestJS – framework Node.js modular e escalável
- TypeScript – tipagem estática
- PostgreSQL – banco de dados relacional
- Redis – armazenamento de tokens e cache de sessões
- TypeORM – ORM para banco PostgreSQL
- bcrypt – hash de senhas
- jsonwebtoken – geração e validação de JWT
- cookie-parser – manipulação de cookies HTTP-only
- @nestjs/throttler – proteção contra brute force (rate limiting)
- helmet – proteção de headers HTTP
- csurf – proteção contra CSRF
- class-validator – validação de entrada de dados (DTOs)
- cors – configuração de Cross-Origin

---

## 🔐 Principais implementações de segurança

### JWT + Refresh Token

- **access_token** → curto prazo, usado para autenticação de requisições.
- **refresh_token** → longo prazo, renova o access_token automaticamente.
- Ambos armazenados em cookies HTTP-only (não acessíveis via JavaScript).
- Tokens armazenados e validados via **Redis** para controle de revogação e gerenciamento de sessões.

### CSRF Protection

- Implementação via double-submit cookie usando csurf.
- Cookie `XSRF-TOKEN` → não httpOnly, lido pelo frontend e enviado no header `X-XSRF-TOKEN`.
- Protege contra requisições CSRF mesmo com cookies enviados automaticamente.

### CORS configurado

- Origin restrito ao frontend.
- `credentials: true` para permitir envio de cookies HTTP-only.

### Helmet

- Protege contra ataques comuns configurando cabeçalhos HTTP (XSS, clickjacking, MIME sniffing).

### Sanitização de inputs

- Evita XSS e injeções SQL/NoSQL dependendo do banco utilizado.

---

## ⚙️ Requisitos

- Node.js >= 20
- NPM >= 9
- PostgreSQL >= 15 (ou via Docker)
- Redis >= 7 (ou via Docker)
- Docker (opcional, recomendado para PostgreSQL e Redis)

---

## 🔧 Instalação

```bash
git clone <repo-url>
cd Auth-NestJS
npm install
```

---

## 🌐 Variáveis de ambiente

Crie `.env`:

```env
PORT=
DATABASE_URL=
REDIS_URL=

JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=

JWT_ACCESS_EXPIRES_IN=
JWT_REFRESH_EXPIRES_IN=

NODE_ENV=
COOKIE_DOMAIN=
```

---

## 🗄 Configuração do banco de dados e Redis

### Usando Docker (recomendado)

**PostgreSQL:**

```bash
docker run --name nest-postgres \
  -e POSTGRES_USER=user \
  -e POSTGRES_PASSWORD=pass \
  -e POSTGRES_DB=dbname \
  -p 5432:5432 -d postgres:15
```

**Redis:**

```bash
docker run --name nest-redis -p 6379:6379 -d redis:7
```

---

## 🚀 Executando o backend

### Desenvolvimento (hot reload)

```bash
npm run dev
```

### Produção (compilação)

```bash
npm run build
npm run start
```

---

## 🔑 Endpoints principais

### 1️⃣ Registrar usuário

```
POST /auth/register
```

**Body (JSON):**

```json
{
  "email": "",
  "password": ""
}
```

- Cria usuário com senha hashada (bcrypt)
- Não requer autenticação

### 2️⃣ Login

```
POST /auth/login
```

**Body (JSON):**

```json
{
  "email": "",
  "password": ""
}
```

**Retorno:**

- Cookies access_token e refresh_token HTTP-only
- Protegido por rate limiting (@Throttle(10,60) por IP)
- Tokens armazenados em Redis para controle de sessões

### 3️⃣ Refresh Token

```
POST /auth/refresh
```

- Renova o access_token usando o refresh_token
- Cookies HTTP-only são atualizados
- Redis é consultado para validar refresh_token

### 4️⃣ Logout

```
POST /auth/logout
```

- Invalida access_token e refresh_token (apaga cookies)
- Tokens removidos do Redis

### 5️⃣ Rotas protegidas

```ts
@UseGuards(JwtAuthGuard)
@Get('profile')
async getProfile() {
  return { message: 'Você acessou uma rota protegida!' };
}
```

- Apenas usuários autenticados podem acessar
- Requer cookie access_token válido

---
