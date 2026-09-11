#!/usr/bin/env python3
"""Generate industrial-depth framework pentest guides (Phase D-M)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORKS = ROOT / "mcp-server" / "rynix_mcp" / "knowledge" / "frameworks"
PRESERVE_IF_LINES_GE = 150

# Unique probe matrices — reduces boilerplate overlap between guides.
STACK_PROBE_MATRIX: dict[str, str] = {
    "express": """| Endpoint pattern | Role A | Role B | IDOR? |
|------------------|--------|--------|-------|
| GET /api/users/:id | 200 own | 403 other | test |
| POST /api/admin/* | 403 user | 200 admin | vertical |
| GET /api/internal/health | 401 | 401 | no leak |""",
    "flask": """| Blueprint | @login_required | Anonymous |
|-----------|-----------------|-----------|
| /api/v1/* | required | 401 |
| /admin/* | staff only | redirect |
| /static/uploads/* | N/A | path traversal |""",
    "gin": """| Group | Middleware | Probe |
|-------|------------|-------|
| /api/v1 | JWT | missing on POST |
| /admin | API key header | brute rotation |
| /ws | none | auth at handshake |""",
    "spring": """| Path | @PreAuthorize | Actuator |
|------|---------------|----------|
| /api/** | authenticated | off in prod |
| /actuator/env | denyAll | must 404 |
| /api/users/{id} | hasRole USER | IDOR |""",
    "laravel": """| Route file | middleware | Policy |
|------------|------------|--------|
| api.php | auth:sanctum | per-model |
| web.php | auth | CSRF |
| /telescope | auth | disable prod |""",
    "rails": """| Resource | before_action | CanCan |
|----------|---------------|--------|
| UsersController | authenticate | authorize |
| Admin:: | admin role | separate namespace |
| ActiveStorage | signed URLs | expiry |""",
    "aspnet": """| Surface | [Authorize] | Minimal API |
|---------|-------------|-------------|
| Controllers | per-action | .RequireAuthorization() |
| SignalR hubs | hub method | per-invoke |
| Blazor | circuit | server auth |""",
    "fastify": """| Route | preHandler | schema.strict |
|-------|------------|---------------|
| /api/* | jwtVerify | additionalProperties false |
| /docs | public | disable prod |
| upload | multipart | filename traversal |""",
    "react": """| Client route | Guard | API must enforce |
|--------------|-------|------------------|
| /dashboard | PrivateRoute | 401 without token |
| /admin | role check | 403 non-admin |
| /api/* | N/A | compare_role_response |""",
    "vue": """| Route meta | beforeEach | Pinia token |
|------------|------------|-------------|
| requiresAuth | block | API still test |
| roles: admin | redirect | horizontal IDOR |
| /api/* | axios interceptor | revoke on 401 |""",
    "nuxt": """| Layer | middleware | server/api |
|-------|------------|------------|
| pages | auth | same rules |
| server/api | often missing | priority target |
| __NUXT__ payload | no secrets | grep HTML |""",
    "angular": """| Guard | CanActivate | lazy module |
|-------|-------------|-------------|
| AuthGuard | route | chunk still loads |
| RoleGuard | data.roles | API enforcement |
| HttpInterceptor | Bearer | refresh race |""",
    "sveltekit": """| File | auth check | risk |
|------|------------|------|
| +page.server.ts | session | data leak in load |
| +server.ts | often open | IDOR |
| hooks.server.ts | set locals | single source |""",
    "graphql": """| Operation | auth directive | batch |
|-----------|----------------|-------|
| Query.users | @auth | field IDOR |
| Mutation.* | role | introspection off |
| subscription | ws auth | topic IDOR |""",
    "trpc": """| Procedure | middleware | input |
|-----------|------------|-------|
| public.* | none | abuse |
| protected.* | isAuthed | Zod strict |
| admin.* | role | batch mix |""",
    "openapi": """| Spec op | security field | live |
|---------|----------------|------|
| listed | bearer | enforce |
| undocumented | fuzz | drift |
| deprecated | should 410 | still live? |""",
    "echo": """| Group | middleware | note |
|-------|------------|------|
| /api | JWT | order |
| root routes | none | gap |
| File | path clean | traversal |""",
    "fiber": """| App route | middleware | fasthttp |
|-----------|------------|----------|
| /api | Locals user | header case |
| static | path | .. segments |
| ws | upgrade | repeat auth |""",
    "chi": """| Mount | Use() chain | subrouter |
|-------|-------------|-----------|
| /api | auth | IDOR ids |
| /admin | separate | mount leak |
| context | user id | propagate |""",
    "axum": """| Router | layer | extractor |
|--------|-------|-----------|
| nest /api | AuthLayer | Path UUID |
| Extension | User | missing 500 |
| ws | handshake | per-msg |""",
    "actix": """| Scope | wrap | guard |
|-------|------|-------|
| /api | HttpAuthentication | IDOR |
| files | NamedFile | traversal |
| admin | Role | vertical |""",
    "koa": """| Middleware order | ctx.state | onion |
|------------------|-----------|-------|
| auth before router | user | gap if after |
| session | secure cookie | fixation |
| body parser | limits | DoS safe |""",
    "hono": """| App | bearerAuth | edge |
|-----|------------|------|
| /api | jwt | env leak |
| rpc | internal | expose |
| validator | zod | bypass CT |""",
    "adonisjs": """| Route | middleware.auth | bouncer |
|-------|-----------------|---------|
| /api | yes | policy per model |
| /admin | role | IDOR |
| drive | signed URL | expiry |""",
    "symfony": """| Firewall | voter | attribute |
|----------|-------|-----------|
| main | lazy | IsGranted |
| api | stateless | JWT |
| admin | ROLE_ADMIN | profiler off |""",
    "quarkus": """| JAX-RS | @RolesAllowed | OIDC |
|--------|---------------|------|
| /api | authenticated | IDOR |
| /q/dev | deny | prod off |
| reactive | separate | auth parity |""",
    "ktor": """| Route | authenticate | plugin |
|-------|--------------|--------|
| /api | block | JWT |
| ws | session | join auth |
| static | block | traversal |""",
    "sinatra": """| App | before filter | namespace |
|-----|---------------|-----------|
| /api | auth | modular gap |
| /admin | admin? | vertical |
| settings | secret | rotate |""",
    "phoenix": """| Pipeline | plug | channel |
|----------|------|---------|
| browser | require user | CSRF |
| api | token | IDOR |
| join | topic | cross-user |""",
}

# stack_id -> (title, description, attack_surface, auth_markers, high_value, vuln_sections, recon)
GUIDES: dict[str, tuple[str, str, str, str, str, str, str]] = {
    "express": (
        "Express",
        "Security testing for Express.js applications covering middleware chains, session/JWT auth, and prototype pollution in Node",
        """**Core**
- `app.use()` middleware order — auth applied after route registration leaks access
- Routers (`express.Router`), nested mounts at `/api`, `/admin`
- Body parsers: `express.json`, `urlencoded`, `multer` for uploads
- Error handlers and `next(err)` — stack trace leakage

**Auth**
- Passport.js strategies (local, JWT, OAuth), `req.user` population
- `express-session` + `connect-redis`, cookie flags
- Custom middleware: `ensureAuthenticated`, role checks on `req.user.role`""",
        "`passport.authenticate`, `req.isAuthenticated`, `req.user`, `jwt.verify`, `ensureLoggedIn`, `authorize(`",
        """- `/api/*` routes mounted without global auth middleware
- Admin routers under `/admin` or `/internal`
- File upload (`multer`) + static `express.static` misconfig
- Webhook/callback URLs accepting user-supplied targets (SSRF)
- GraphQL mounted via `express-graphql` with introspection enabled""",
        """### Authentication gaps
- Route registered before `passport.session()` middleware
- JWT in header verified but `req.user` never bound — handlers trust client-sent `userId`
- Role check only in UI, not in API route

### Prototype pollution / mass assignment
- `Object.assign(req.body, defaults)` without schema validation
- Lodash `merge` on user input — test `__proto__`, `constructor.prototype`

### Injection
- `eval`, `vm`, template engines (EJS, Pug, Handlebars) with user input
- NoSQL (`$gt`, `$where`) when using Mongoose without sanitization
- Raw SQL via `mysql2`/`pg` string concatenation bypassing ORM

### CORS / CSRF
- `cors({ origin: true })` reflecting arbitrary Origin with credentials
- Cookie auth without `SameSite` + missing CSRF token on state-changing routes""",
        """```
GET /api/health
GET /api/users/1  (IDOR matrix)
curl -H "Authorization: Bearer <token>" /api/admin/users
# Fingerprint: X-Powered-By: Express (disable in prod)
```""",
    ),
    "flask": (
        "Flask",
        "Security testing for Flask/Werkzeug apps — decorators, Jinja2 SSTI, session signing, and blueprint auth drift",
        """**Core**
- Blueprints (`Blueprint`, `register_blueprint`) with independent before_request hooks
- `@app.route` decorators, method lists, `strict_slashes`
- Jinja2 templates, `render_template`, `|safe` filter abuse
- Werkzeug debugger PIN bypass when `debug=True`

**Auth**
- Flask-Login (`@login_required`, `current_user`)
- Flask-JWT-Extended, Flask-HTTPAuth
- `@roles_required`, custom decorators inconsistently applied""",
        "`@login_required`, `login_required`, `current_user`, `@jwt_required`, `roles_required`, `permission_required`",
        """- `/admin`, Flask-Admin panel
- Debug toolbar, Werkzeug interactive debugger
- Secret key dependent endpoints (itsdangerous signed URLs)
- File download `send_file` with user-controlled paths
- Celery/RQ task enqueue with object IDs""",
        """### Session / crypto
- Weak or default `SECRET_KEY` — forge session cookies
- `SESSION_COOKIE_SECURE=False` on HTTPS deployment

### SSTI (Jinja2)
```
{{7*7}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### IDOR
- Blueprint without `before_request` auth on subset of routes
- API returning 404 vs 403 — information leak on object existence""",
        """```
curl -I https://target/
GET /login  /admin  /api/v1/
# Check Set-Cookie: session=...
```""",
    ),
    "gin": (
        "Gin",
        "Security testing for Gin (Go) — middleware chains, JWT groups, binding validation, and goroutine race windows",
        """**Core**
- `gin.Engine`, route groups `r.Group("/api")`
- Middleware: `Use()`, group-level vs route-level
- `ShouldBindJSON`, `BindJSON`, validator tags
- `gin.H` map responses — avoid leaking internal errors

**Auth**
- JWT middleware (`jwt-go`, custom `AuthMiddleware`)
- API key headers, basic auth on admin routes""",
        '`jwt`, `AuthMiddleware`, `middleware.Auth`, `c.Get("user")`, `Authorize`, `RequireRole`',
        """- `r.Group(\"/api/v1\")` with mixed protected/unprotected routes
- Admin group `/admin` behind weak shared secret header
- File handlers `c.File`, `c.FileAttachment`
- WebSocket upgrade handlers without repeating HTTP auth""",
        """### Middleware ordering
- Public routes registered on root engine bypassing group middleware
- CORS middleware allowing credentials from reflected Origin

### Binding bypass
- Duplicate JSON keys, wrong Content-Type to skip `ShouldBind`
- Integer overflow on path params (`/users/-1`)

### Concurrency
- Race on balance/quantity updates — parallel `http_probe` batch""",
        """```
GET /api/health
GET /api/users/1
Authorization: Bearer <jwt>
```""",
    ),
    "spring": (
        "Spring Boot",
        "Security testing for Spring Boot — SecurityFilterChain, `@PreAuthorize`, SpEL, Actuator, and JPA injection",
        """**Core**
- `@RestController`, `@RequestMapping`, path variables
- Spring Security filter chain order, `permitAll` vs `authenticated`
- Actuator endpoints (`/actuator/*`), env, heapdump
- Thymeleaf / Freemarker if present

**Auth**
- `@PreAuthorize`, `@Secured`, `@RolesAllowed`
- OAuth2 Resource Server, JWT decoder configuration
- Method security vs URL security mismatch""",
        "`@PreAuthorize`, `@Secured`, `SecurityFilterChain`, `hasRole`, `hasAuthority`, `@EnableMethodSecurity`",
        """- `/actuator/env`, `/actuator/heapdump`, `/actuator/gateway/routes`
- Swagger UI `/swagger-ui.html`, `/v3/api-docs`
- Admin `@PreAuthorize(\"hasRole('ADMIN')\")` — test horizontal escalation
- File upload `MultipartFile`, path traversal in storage""",
        """### SpEL injection
- `@Value` or custom expressions in `@PreAuthorize` with user input
- Spring Data `sort` parameter injection

### Mass assignment
- `@RequestBody` entity binding extra fields (`isAdmin=true`)
- Jackson `JsonIgnoreProperties` misconfiguration

### IDOR
- Repository `findById` without ownership check in service layer""",
        """```
GET /actuator/health
GET /v3/api-docs
GET /api/users/1
```""",
    ),
    "laravel": (
        "Laravel",
        "Security testing for Laravel — gates, policies, mass assignment, debug mode, and route middleware",
        """**Core**
- `routes/web.php`, `routes/api.php`, `Route::` groups
- Middleware `auth`, `can`, `throttle`
- Eloquent ORM, raw `DB::select`
- Blade templates, `{!! !!}` unescaped output

**Auth**
- `Gate::`, `Policy` classes, `@can` directives
- Sanctum, Passport API tokens
- `Auth::user()`, middleware `auth:sanctum`""",
        "`middleware('auth'`, `->middleware(`, `Gate::`, `authorize(`, `auth:sanctum`, `@can`",
        """- `/telescope`, `/horizon`, `/_ignition` when debug enabled
- `APP_DEBUG=true` exposing `.env` via error pages
- API resources returning hidden attributes leak via `append`
- Storage symlink `public/storage` path traversal""",
        """### Mass assignment
- `$fillable` / `$guarded` misconfiguration on User model
- `create($request->all())` on sensitive models

### Policy gaps
- `view` authorized but `update`/`delete` missing policy checks
- API routes without `auth` middleware in `api.php`

### SQL injection
- `whereRaw`, `orderByRaw` with concatenated user input""",
        """```
GET /api/user
GET /sanctum/csrf-cookie
php artisan route:list  (whitebox via analyze_repo)
```""",
    ),
    "rails": (
        "Rails",
        "Security testing for Ruby on Rails — strong parameters, CSRF, ActiveRecord SQLi, and Devise auth",
        """**Core**
- `config/routes.rb`, RESTful resources, namespaces
- `before_action :authenticate_user!`
- ActiveRecord, `find_by_sql`, scopes
- ERB templates, `html_safe` abuse

**Auth**
- Devise, `current_user`, `authorize!` (CanCanCan)
- Doorkeeper OAuth, API-only mode without CSRF""",
        "`before_action :authenticate`, `current_user`, `authorize!`, `doorkeeper_authorize!`, `protect_from_forgery`",
        """- `/rails/info/properties`, `/rails/mailers` in development mis-deployed
- ActiveStorage direct upload URLs
- Sidekiq Web UI `/sidekiq`
- GraphQL mount without per-field authorization""",
        """### Mass assignment
- `permit!` or missing strong parameters on `params.require`
- `attr_accessible` legacy apps

### SQL injection
- `where(\"name = '#{params[:q]}'\")` string interpolation
- `order(params[:sort])` without allowlist

### IDOR
- `User.find(params[:id])` without scoping to `current_user`""",
        """```
GET /users/sign_in
GET /api/v1/users/1
X-CSRF-Token: ... (for cookie auth)
```""",
    ),
    "aspnet": (
        "ASP.NET Core",
        "Security testing for ASP.NET Core — `[Authorize]`, policy handlers, antiforgery, and minimal APIs",
        """**Core**
- Controllers, Minimal APIs (`MapGet`, `MapPost`)
- Middleware pipeline order — auth before endpoints
- `IAuthorizationService`, policy-based auth
- Razor Pages, tag helpers

**Auth**
- `[Authorize(Roles = \"Admin\")]`, `[AllowAnonymous]`
- JWT Bearer, cookie auth, OpenID Connect
- Claims-based authorization""",
        "`[Authorize]`, `[AllowAnonymous]`, `RequireAuthorization`, `AddAuthorization`, `IAuthorizationHandler`",
        """- Swagger `/swagger`, health checks exposing dependencies
- SignalR hubs without `[Authorize]` on hub methods
- Blazor Server circuit authorization gaps
- `IFormFile` upload path traversal""",
        """### Policy bypass
- Minimal API endpoint missing `.RequireAuthorization()`
- `[AllowAnonymous]` on nested controller action only

### Mass assignment
- Model binding over-posting to entity with sensitive properties
- `JsonSerializer` missing `[JsonIgnore]` on admin flags

### Deserialization
- `TypeNameHandling` in Newtonsoft.Json (legacy configs)""",
        """```
GET /health
GET /swagger/v1/swagger.json
GET /api/users/1
Authorization: Bearer <token>
```""",
    ),
    "fastify": (
        "Fastify",
        "Security testing for Fastify — JSON schema validation, hooks lifecycle, and plugin encapsulation",
        """**Core**
- Route schemas (`schema.body`, `response`) — validation bypass via extra keys
- `onRequest`, `preHandler`, `preValidation` hooks
- Plugin encapsulation — auth plugin not applied to nested plugins
- `@fastify/multipart`, `@fastify/static`

**Auth**
- `@fastify/jwt`, custom `preHandler` auth
- Role decorators in TypeScript routes""",
        "`preHandler`, `@fastify/jwt`, `request.user`, `authenticate`, `onRequest`",
        """- Routes registered outside authenticated plugin scope
- `/documentation` Swagger in production
- WebSocket `@fastify/websocket` without JWT repeat check""",
        """### Schema bypass
- `additionalProperties: true` allowing privilege fields
- Content-Type switching to skip JSON schema validation

### Hook ordering
- `preValidation` skipped when `attachValidation: false`

### IDOR
- Handler trusts `request.params.id` without tenant scoping""",
        """```
GET /health
GET /api/users/1
```""",
    ),
    "react": (
        "React",
        "Security testing for React SPAs — client-side routes, token storage, API coupling, and XSS sinks",
        """**Core**
- React Router (`Route`, `Navigate`, protected route wrappers)
- State management exposing secrets in bundle
- `dangerouslySetInnerHTML`, DOMPurify misconfig
- Environment variables baked into `VITE_*` / `REACT_APP_*`

**API coupling**
- Bearer tokens in `localStorage` vs `httpOnly` cookies
- CORS preflight differences per API path""",
        '`PrivateRoute`, `useAuth`, `Navigate to="/login"`, `Authorization: Bearer`',
        """- `/admin`, `/dashboard` routes — test direct URL access (client-only guard)
- API base URL in bundle pointing to staging with weaker auth
- WebSocket subscriptions keyed by predictable IDs""",
        """### Client-side auth bypass
- Route guard only in React — API must enforce server-side
- JWT in localStorage — XSS steals token

### XSS
- `dangerouslySetInnerHTML` with partial sanitization
- Third-party script tags in CMS-driven React pages

### IDOR
- Frontend hides buttons but API returns other users' data""",
        """```
# list_frontend_routes from analyze_repo
GET /dashboard  (without auth cookie)
GET /api/users/1  (compare_role_response)
```""",
    ),
    "vue": (
        "Vue",
        "Security testing for Vue 3 — router guards, Pinia auth state, and template injection",
        """**Core**
- Vue Router `beforeEach` navigation guards
- Composition API `ref`/`reactive` storing tokens
- `v-html` directive XSS sink
- Nuxt overlap — see nuxt.md for SSR

**Auth**
- `meta: { requiresAuth: true }` on routes
- Axios interceptors attaching JWT""",
        "`beforeEach`, `requiresAuth`, `meta.roles`, `router.beforeEach`, `useAuthStore`",
        """- Lazy-loaded admin chunks still downloadable
- `/api` proxy misconfiguration in dev server deployed to prod
- WebSocket channels keyed by user ID in query string""",
        """### Guard bypass
- Direct API calls skipping router guards
- `requiresAuth` only on parent route — child routes open

### XSS
- `v-html` with user content
- Server-side template injection if using Vue SSR without escaping""",
        """```
# router.ts paths from analyze_repo
GET /settings
GET /api/profile
```""",
    ),
    "nuxt": (
        "Nuxt",
        "Security testing for Nuxt 3 — server routes, middleware, auth module, and SSR data leaks",
        """**Core**
- `definePageMeta({ middleware: 'auth' })`
- Server routes `server/api/*.ts` — often weaker than pages
- `useFetch`, `useAsyncData` exposing secrets in HTML payload
- Nitro server handlers

**Auth**
- `@sidebase/nuxt-auth`, custom `auth` middleware
- Route rules in `nuxt.config`""",
        "`definePageMeta`, `middleware:`, `server/api`, `useAuth`, `navigateTo`",
        """- `/api/_nuxt` build manifest revealing all routes
- Server API routes without mirroring page middleware
- `runtimeConfig` public vs private key confusion""",
        """### SSR data leakage
- Sensitive fields serialized into `__NUXT__` payload
- Server route returns internal fields not filtered for client

### Auth middleware gaps
- `middleware/auth.ts` not applied to `/api/*` server routes""",
        """```
GET /api/health
GET /dashboard
# Inspect __NUXT_DATA__ in HTML source
```""",
    ),
    "angular": (
        "Angular",
        "Security testing for Angular — route guards, interceptors, and template sanitization bypass",
        """**Core**
- `CanActivate`, `CanActivateChild`, `CanLoad` guards
- HTTP interceptors adding `Authorization`
- DomSanitizer bypass research (bypassSecurityTrust*)
- Lazy modules with separate guard registration

**Auth**
- `AuthGuard` service, role-based `*ngIf` only in template""",
        "`CanActivate`, `AuthGuard`, `HttpInterceptor`, `router.navigate`, `hasRole`",
        """- Admin lazy modules — test loading `/admin` module chunks
- Environment.ts API URLs and feature flags in bundle
- GraphQL Apollo client with stored tokens""",
        """### Guard bypass
- Resolver fetches data before guard completes (race)
- API not validating roles that UI hides

### XSS
- `bypassSecurityTrustHtml` misuse
- Custom elements shadow DOM escaping sanitizer""",
        """```
GET /admin
GET /api/users/1
```""",
    ),
    "sveltekit": (
        "SvelteKit",
        "Security testing for SvelteKit — server hooks, form actions, and `+server.ts` endpoints",
        """**Core**
- `+page.server.ts`, `+layout.server.ts` load functions
- `hooks.server.ts` `handle` sequence auth
- Form actions `+page.server.ts` `actions`
- `+server.ts` API routes parallel to pages

**Auth**
- `event.locals.user` populated in hooks
- Session cookies via `cookies.set`""",
        "`handle`, `event.locals`, `hooks.server`, `getSession`, `protect`",
        """- `+server.ts` endpoints missing session check present in `+page.server.ts`
- `prerender` exposing dynamic routes statically
- `PUBLIC_` env vars in client bundle""",
        """### Server/client boundary
- Sensitive data in `load` returned to client unnecessarily
- CSRF on form actions when SameSite misconfigured

### IDOR
- `params.id` in load function without ownership validation""",
        """```
GET /api/health
GET /dashboard
```""",
    ),
    "graphql": (
        "GraphQL",
        "Security testing for GraphQL APIs — introspection, batching, depth limits, and resolver auth",
        """**Core**
- Schema introspection `__schema`, `__type`
- Queries, mutations, subscriptions
- Field-level auth vs object-level
- DataLoader batching IDOR windows

**Stacks**
- Apollo Server, Yoga, Strawberry, Graphene — resolver patterns differ""",
        "`@auth`, `@permission`, `shield`, `rule`, `isAuthenticated`, `context.user`",
        """- Introspection enabled in production
- GraphiQL/Playground exposed
- `users { id email passwordHash }` over-fetching
- Batching attack combining privileged + unprivileged queries""",
        """### Authorization
- Resolver checks parent auth but field resolvers skip check
- Global ID enumeration across types

### DoS
- Deep nested queries without cost analysis
- Alias overload batching""",
        """```
POST /graphql
{"query":"{ __schema { types { name } } }"}
```""",
    ),
    "trpc": (
        "tRPC",
        "Security testing for tRPC — procedure middleware, input validation, and batching",
        """**Core**
- `publicProcedure`, `protectedProcedure`, `adminProcedure`
- Zod input schemas — `.strict()` vs permissive
- `createCaller` server-side bypass of HTTP layer
- HTTP batching `trpc.batch`""",
        "`protectedProcedure`, `middleware`, `ctx.session`, `isAuthed`, `adminProcedure`",
        """- `publicProcedure` exposing internal procedures
- Batched requests mixing auth contexts
- OpenAPI adapter exposing full procedure map""",
        """### Procedure exposure
- Router merge accidentally exposing admin procedures on public router
- Missing `.use(isAuthed)` on subset of procedures

### Input validation
- Zod `passthrough()` allowing extra keys into database""",
        """```
POST /api/trpc/user.get?batch=1
```""",
    ),
    "openapi": (
        "OpenAPI",
        "Security testing for OpenAPI-described APIs — spec vs implementation drift and undocumented paths",
        """**Core**
- Static `openapi.json` / `swagger.yaml` vs live routes
- Security schemes: bearer, apiKey, oauth2
- Undocumented paths found via fuzzing vs spec

**Usage**
- Merge spec endpoints with `analyze_repo` routes for gap analysis""",
        "`security`, `bearerAuth`, `apiKey`, `oauth2`, `components.securitySchemes`",
        """- Spec lists auth but implementation omits on subset of paths
- `deprecated` endpoints still live
- Internal paths in spec marked public""",
        """### Spec drift
- Implementation accepts methods not in spec (verb tampering)
- Required security scheme not enforced on all operations

### IDOR
- Path params in spec without tenant scoping documented — test anyway""",
        """```
GET /openapi.json
GET /swagger.json
# Diff with list_api_routes output
```""",
    ),
    "echo": (
        "Echo",
        "Security testing for Echo (Go) — middleware, groups, binding, and JWT",
        """**Core**
- `echo.New()`, route groups `e.Group`
- Middleware `Use`, `Pre`, `Post`
- `Bind`, `Validate` on structs
- Custom HTTPErrorHandler information leak""",
        '`middleware.JWT`, `echojwt`, `KeyAuth`, `BasicAuth`, `c.Get("user")`',
        """- Group `/api` with JWT middleware — test routes registered on `e` directly
- File routes `c.File`, path traversal
- WebSocket routes without JWT""",
        """### Middleware scope
- Routes on root Echo bypassing group middleware
- JWT only on `Authorization` header — cookie auth forgotten

### Binding
- Struct tags ignored when Content-Type is wrong""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "fiber": (
        "Fiber",
        "Security testing for Fiber (Go) — fasthttp handlers, middleware, and CSRF",
        """**Core**
- `app.Get`, `app.Group`, `fiber.Map`
- Middleware chain — order matters
- `BodyParser`, validator middleware
- fasthttp-specific header handling differences""",
        '`jwtware`, `keyauth`, `basicauth`, `c.Locals("user")`, `middleware.Auth`',
        """- Static files `app.Static` exposing build artifacts
- Prefork mode shared state race conditions
- WebSocket `websocket.New` without auth""",
        """### fasthttp quirks
- Case sensitivity on headers differs from net/http proxies
- Path normalization `%2e%2e` bypass attempts

### Auth locals
- Handler reads `c.Locals(\"user\")` without middleware on route""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "chi": (
        "Chi",
        "Security testing for chi router (Go) — sub-routers, middleware stacks, URL params",
        """**Core**
- `chi.NewRouter()`, `r.Route`, `r.Mount`
- `middleware` package — `Recoverer`, `Authenticator`
- `URLParam`, `Decode` — path param injection
- Compatible with stdlib `http.Handler`""",
        "`middleware.Authenticator`, `jwtauth`, `FromContext`, `r.Use`",
        """- `r.Mount(\"/admin\", adminRouter)` — admin router missing auth
- Route patterns `/users/{userID}` IDOR
- CORS `cors.Handler` overly permissive""",
        """### Sub-router isolation
- Mounted router without shared auth middleware
- Context values not propagated across mounts

### IDOR
- `URLParam(r, \"id\")` used directly in SQL without ownership""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "axum": (
        "Axum",
        "Security testing for Axum (Rust) — extractors, layers, Tower middleware, and typed routes",
        """**Core**
- `Router::new()`, `route`, `nest`
- Tower layers: `Extension`, `AuthLayer`, rate limit
- Extractors: `Path`, `Query`, `Json`, `TypedHeader`
- `State` shared application state races

**Auth**
- Custom `FromRequestParts` for JWT/session
- `tower_http::auth` patterns""",
        "`FromRequestParts`, `Extension<User>`, `AuthLayer`, `require_auth`, `Claims`",
        """- `nest(\"/api\", public_router)` leaking admin routes
- `Debug` error responses in production
- WebSocket upgrade handlers""",
        """### Extractor failures
- `Option<Json<T>>` silently accepting empty body
- Auth extension missing returns 500 vs 401 — info leak

### IDOR
- `Path(uuid)>` without row-level check in handler""",
        """```
GET /api/health
GET /api/users/{id}
```""",
    ),
    "actix": (
        "Actix Web",
        "Security testing for Actix Web — guards, apps, scopes, and async handler auth",
        """**Core**
- `App::new().service`, `web::scope`
- `wrap` middleware order
- `web::Json`, `Validator` crate
- `HttpResponse` error detail leakage

**Auth**
- `HttpAuthentication` middleware, `Identity` service""",
        "`HttpAuthentication`, `Identity`, `authorize`, `#[guard]`, `require_auth`",
        """- Scope `/api` vs root `App` service registration gaps
- `actix-files` directory traversal
- Actor mailbox authorization (if actix actors used)""",
        """### Scope registration
- Routes on `App` bypassing `web::scope` middleware
- `JsonConfig` limit bypass with chunked encoding

### IDOR
- `web::Path<UserId>` without database ownership filter""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "koa": (
        "Koa",
        "Security testing for Koa — async middleware onion, ctx.state, and JWT",
        """**Core**
- `app.use` middleware onion — first registered = outermost
- `ctx.state`, `ctx.request.body`
- `@koa/router` route-level middleware
- Error event listener stack traces""",
        "`ctx.state.user`, `jwt`, `koa-jwt`, `session`, `isAuthenticated`",
        """- Router middleware not applied when mounting with `prefix` mismatch
- `koa-static` serving `.env` if misconfigured
- GraphQL koa mount""",
        """### Middleware onion
- Auth middleware after router — never runs for matched routes
- `ctx.throw` leaking internal messages

### Session
- `koa-session` without `secure` on HTTPS""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "hono": (
        "Hono",
        "Security testing for Hono — edge workers, middleware, Zod validator, and multi-runtime",
        """**Core**
- `app.use`, `app.route`, sub-apps `app.basePath`
- `@hono/zod-validator` — schema strictness
- Runs on Cloudflare Workers, Deno, Node — different env secret exposure
- `c.req.param`, `c.req.query`""",
        "`jwt`, `bearerAuth`, `basicAuth`, `c.get('user')`, `verify`",
        """- Worker env `JWT_SECRET` in bundle if misconfigured
- Admin routes on same app without `use('*', auth)`
- RPC-style internal routes `/rpc/*`""",
        """### Edge secrets
- `c.env` bindings logged in error responses
- Validator skipped on `Content-Type: text/plain`

### IDOR
- Multi-tenant `c.get('tenant')` not validated against resource""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "adonisjs": (
        "AdonisJS",
        "Security testing for AdonisJS — bouncer policies, Lucid ORM, and HTTP context auth",
        """**Core**
- `routes.ts`, controller middleware `middleware.auth()`
- Bouncer `authorize` policies
- Lucid models, raw queries
- Edge SSR templates""",
        "`middleware.auth`, `bouncer.authorize`, `auth.use`, `ctx.auth`",
        """- `/admin` routes missing `middleware.auth`
- Drive file uploads public URL generation
- Inertia/Vue pages with client-only guards""",
        """### Bouncer gaps
- Policy on controller action but not on related API resource
- `auth.user` trusted without `isActive` check

### Mass assignment
- Lucid `fill` with unguarded columns""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "symfony": (
        "Symfony",
        "Security testing for Symfony — voters, firewalls, attributes, and Doctrine",
        """**Core**
- `#[Route]`, `security.yaml` firewalls, access_control
- Voters `is_granted`, `#[IsGranted]`
- Doctrine repositories, DQL injection
- Twig templates, `|raw` filter

**Auth**
- Symfony Security component, JWT (lexik), API Platform""",
        "`#[IsGranted]`, `is_granted`, `security.yaml`, `ROLE_`, `Voter`",
        """- `_profiler`, `_wdt` in production
- API Platform `/api` hypermedia exposing all resources
- Maker bundle dev routes""",
        """### Firewall mismatch
- `access_control` path regex bypass with trailing slash
- Stateless API firewall accepting session cookies

### IDOR
- Voter checks type but not instance ownership""",
        """```
GET /api/health
GET /_profiler  (should 404 in prod)
GET /api/users/1
```""",
    ),
    "quarkus": (
        "Quarkus",
        "Security testing for Quarkus — JAX-RS, Panache, OIDC, and reactive routes",
        """**Core**
- JAX-RS `@Path`, `@GET`, `@RolesAllowed`
- Quarkus Security OIDC, JWT
- Hibernate Panache `findById`
- Reactive routes `Route` vertx""",
        "`@RolesAllowed`, `@Authenticated`, `SecurityIdentity`, `@PermitAll`, `quarkus-oidc`",
        """- `/q/dev` UI in production
- OpenAPI `/q/openapi`
- GraphQL smallrye without field auth""",
        """### JAX-RS gaps
- `@PermitAll` on class, `@RolesAllowed` missing on method
- Reactive route bypassing JAX-RS security

### IDOR
- Panache `findById` without tenant filter""",
        """```
GET /q/health
GET /api/users/1
```""",
    ),
    "ktor": (
        "Ktor",
        "Security testing for Ktor — plugins, routing, JWT, and SSE/WebSocket",
        """**Core**
- `routing { }`, `authenticate` block
- Plugins: Authentication, ContentNegotiation, StatusPages
- `call.receive`, kotlinx.serialization
- WebSocket sessions""",
        "`authenticate`, `authorize`, `principal`, `jwt`, `UserIdPrincipal`",
        """- Route outside `authenticate` block with same path prefix
- Static content `staticFiles` path traversal
- Admin routes on separate port without auth""",
        """### Plugin order
- `StatusPages` exposing stack traces
- CORS plugin allowing credentials from any origin

### IDOR
- `call.parameters[\"id\"]` without ownership in repository""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "sinatra": (
        "Sinatra",
        "Security testing for Sinatra — classic Ruby DSL routes, sessions, and Rack middleware",
        """**Core**
- `get '/path' do` DSL, modular Sinatra apps
- Rack middleware stack order
- `params`, `settings` exposure
- ERB templates in views""",
        "`use Rack::Protection`, `session`, `authorized?`, `before do`, `halt 401`",
        """- `/admin` namespace in modular app without `before` filter
- `enable :show_exceptions` in production
- Sidekiq/Resque web UIs mounted""",
        """### before filter scope
- `before` only in submodule — parent routes unprotected
- Session secret default in `config.ru`

### IDOR
- `User.find(params[:id])` without `current_user` scope""",
        """```
GET /api/health
GET /api/users/1
```""",
    ),
    "phoenix": (
        "Phoenix",
        "Security testing for Phoenix/Elixir — plugs, LiveView, channels, and Ecto",
        """**Core**
- Router `pipe_through`, plugs pipeline
- Controllers, LiveView `mount` auth
- Channels `join` authorization
- Ecto queries, `fragment` SQL injection

**Auth**
- `plug :require_authenticated_user`
- Guardian, Auth0 integrations""",
        "`plug :require`, `pipe_through`, `Guardian.Plug`, `assign(:current_user`, `authorize`",
        """- `/dev/dashboard` in production
- LiveView mount without auth — socket hijack
- Channel `join(\"room:\" <> id)` IDOR""",
        """### Plug pipeline
- API pipeline missing `:authenticated` plug used in browser pipeline
- LiveView session not matching API token user

### IDOR
- `Repo.get!(User, id)` without org scoping""",
        """```
GET /api/health
GET /live/dashboard
WebSocket channel join tests
```""",
    ),
}


def render(stack_id: str, data: tuple[str, ...]) -> str:
    title, desc, attack, auth, targets, vulns, recon = data
    probe_matrix = STACK_PROBE_MATRIX.get(
        stack_id,
        "| Route | Auth marker | IDOR probe |\n|-------|-------------|-------------|\n| /api/* | see static analysis | `run_idor_matrix` |",
    )
    return f"""---
name: {stack_id}
description: {desc}
---

# {title}

{desc}. Map routes with `analyze_repo` (stack hint `{stack_id}`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

{attack}

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: {auth}.

## High-Value Targets

{targets}

## Reconnaissance

{recon}

## Key Vulnerabilities

{vulns}

## Stack-specific probe matrix

{probe_matrix}

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `{stack_id}`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["{stack_id}"]` in profile `[scanner]` for dedicated extractor routing.
- Review `analyze_repo` warnings for `generic_extractor_used` — expand `api_roots` if triggered.
- Cross-check routes from `list_api_routes` against auth markers listed above.

## Bypass techniques

- Content-Type and method override (`X-HTTP-Method-Override`, `_method` parameter).
- Path normalization (`/api/users/1/`, `/api/users/1%2f`, case variants).
- Duplicate parameters and JSON key precedence in binding layers.
- Race parallel requests on state-changing endpoints (limits, balances, invites).

## Validation requirements

- Side-by-side `compare_role_response` for owner vs non-owner on object IDs.
- Static `rbac_matrix` citation (file:line) for routes missing auth markers.
- Minimal safe payloads only — document exact request that proves the flaw.
- Session ID on every live tool call; findings via `record_finding` with probe hash.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["{stack_id}"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
"""


def main() -> int:
    written = 0
    skipped = 0
    for stack_id, data in GUIDES.items():
        path = FRAMEWORKS / f"{stack_id}.md"
        if (
            path.is_file()
            and len(path.read_text(encoding="utf-8").splitlines()) >= PRESERVE_IF_LINES_GE
        ):
            print(f"skip {path.name} (preserved deep guide)")
            skipped += 1
            continue
        content = render(stack_id, data)
        path.write_text(content, encoding="utf-8")
        written += 1
        lines = len(content.splitlines())
        print(f"wrote {path.name} ({lines} lines)")
    print(f"generated {written} framework guides ({skipped} preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
