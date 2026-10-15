---
name: bug-hunting-recon-surface
description: >-
  Attack surface discovery, AST route extraction, middleware hierarchy, and IP/header spoofing audits.
  Use when mapping application endpoints, permission tiers, unauthenticated routes, and sensitive sinks.
---

# Bug Hunting: Attack Surface Reconnaissance

This skill guides the discovery and modeling of an application's complete attack surface prior to vulnerability hunting.

---

## 1. Route & Entry Point Extraction

1. **Scan Route Definitions:**
   - Express/Fastify: Search for `app.get`, `app.post`, `app.use`, `router.route`, `express.Router()`.
   - Next.js / Serverless: Inspect `app/api/**/route.js`, `pages/api/**`, Cloudflare Workers (`export default { fetch }`).
   - Python: Inspect `@app.route`, `@router.get`, `urls.py`.
2. **Extract Parameter Shapes:**
   - Route params: `:id`, `:tenantId`, `[slug]`.
   - Query params: `req.query`, `request.args`.
   - Body schemas: `req.body`, Zod/Joi schemas, Pydantic models.
   - Header dependencies: `req.headers['x-forwarded-for']`, `authorization`, `x-tenant-id`.
3. **Map Alternative Protocols:**
   - WebSockets: `io.on('connection')`, `ws.on('message')`.
   - GraphQL: `/graphql`, Apollo/Yoga schema resolvers.
   - Message Queues: Consumers for SQS, RabbitMQ, Kafka.

---

## 2. Authentication & Authorization Boundaries

Classify every discovered endpoint into one of three security tiers:

| Tier | Name | Criteria | Examples |
|---|---|---|---|
| **Tier 0** | Public / Unauthenticated | No auth middleware applied. Accessible by anonymous internet traffic. | `/api/auth/login`, `/api/register`, `/health`, `/public/*` |
| **Tier 1** | Authenticated User | Requires valid session/JWT, but standard user privilege. | `/api/profile`, `/api/documents`, `/api/orders` |
| **Tier 2** | Privileged / Admin | Requires elevated roles (`admin`, `manager`, internal). | `/api/admin/*`, `/api/users/delete`, `/api/metrics` |

### Audit Steps:
- Check for **Middleware Gaps:** Look for routes added after global router middleware or routes missing explicit auth guards.
- Check for **IP/Header Spoofing:** Audit trust proxies (`app.set('trust proxy', true)`). Verify whether authorization decisions rely on spoofable headers (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`).

---

## 3. Sensitive Sink Discovery

Trace every external interaction to identify potential targets for injection or exfiltration:

- **Database Sinks:**
  - Raw SQL: `db.query`, `client.execute`, `sequelize.literal`, `prisma.$queryRawUnsafe`.
  - NoSQL: `collection.find`, `Model.findOne`, MongoDB object filters.
- **System Execution Sinks:**
  - Node: `child_process.exec`, `execSync`, `spawn`.
  - Python: `os.system`, `subprocess.Popen`.
- **File System Sinks:**
  - `fs.readFile`, `fs.writeFile`, `path.join(base, userPath)`.
- **Outbound HTTP Sinks (SSRF):**
  - `axios.get`, `fetch`, `http.request`, `got`.

---

## 4. Output: Attack Surface Map

Format the reconnaissance output as a structured table before proceeding to vulnerability hunting:

```markdown
### Attack Surface Summary
- **Total Routes Discovered:** [Count]
- **Tier 0 (Public) Routes:** [List routes]
- **High-Risk Sinks Identified:** [List file/line numbers of DB/System/HTTP sinks]
```

Next step: dispatch specific hunting routines ([vuln-hunting-injection-rce](../vuln-hunting-injection-rce/SKILL.md) or [vuln-hunting-auth-access-control](../vuln-hunting-auth-access-control/SKILL.md)).
