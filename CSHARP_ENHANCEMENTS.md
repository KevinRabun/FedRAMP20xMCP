# C# Analyzer Enhancement Plan

## Current Status
**Coverage:** 28 KSIs (38.9%) - Phases 1-5 Complete
**Strengths:**
- ✅ FluentValidation Deep Support (December 2024)
- ✅ AST-based analysis with tree-sitter
- ✅ Framework detection (Data Annotations, Application Insights, Data Protection API)
- ✅ Configuration file analysis (appsettings.json)
- ✅ Cross-method data flow tracking
- ✅ Dependency vulnerability checking

## Enhancement Goals
**Focus:** Deepen existing KSI coverage with advanced .NET/Azure patterns
**Timeline:** 2-3 weeks
**Priority:** HIGH - Improves accuracy and reduces false positives

---

## Phase A: Entity Framework Security (KSI-SVC-02, SVC-01)

### 1. SQL Injection via LINQ/EF ✨ NEW
**Current Gap:** Only detects string concatenation, misses dangerous EF patterns
**KSI:** SVC-02 (Input Validation)

**Detection Patterns:**
```csharp
// ❌ BAD: Raw SQL with string interpolation
context.Database.ExecuteSqlRaw($"SELECT * FROM Users WHERE Id = {userId}");
context.Database.ExecuteSqlInterpolated($"DELETE FROM {tableName}");

// ❌ BAD: FromSqlRaw with concatenation
context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");

// ❌ BAD: Dynamic LINQ with string building
var query = $"Name == \"{userInput}\"";
context.Users.Where(query);

// ✅ GOOD: Parameterized queries
context.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Id = {0}", userId);
context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {userId}");

// ✅ GOOD: LINQ (automatically parameterized)
context.Users.Where(u => u.Id == userId);
```

**Implementation:**
- Detect `ExecuteSqlRaw` without parameters
- Detect `FromSqlRaw` with string concatenation
- Detect string interpolation in SQL methods
- Recommend parameterized alternatives

### 2. EF Core N+1 Query Detection 🔍 NEW
**Current Gap:** No performance/security analysis
**KSI:** SVC-01 (Error Handling) - performance errors

**Detection Patterns:**
```csharp
// ❌ BAD: N+1 problem - missing Include
foreach (var order in context.Orders) {
    // Each iteration triggers separate query
    var customer = order.Customer.Name;
}

// ✅ GOOD: Eager loading with Include
var orders = context.Orders.Include(o => o.Customer).ToList();

// ✅ GOOD: Projection to avoid loading entire entities
var orders = context.Orders.Select(o => new { o.Id, CustomerName = o.Customer.Name });
```

**Implementation:**
- Detect foreach loops iterating EF collections
- Check for navigation property access without Include()
- Suggest Include(), ThenInclude(), or projection patterns

### 3. EF Tracking vs No-Tracking 📊 NEW
**KSI:** SVC-01 (Performance), MLA-06 (Performance Monitoring)

**Detection Patterns:**
```csharp
// ❌ BAD: Tracking queries for read-only data
var users = context.Users.ToList(); // Tracking enabled by default

// ✅ GOOD: No-tracking for read-only queries
var users = context.Users.AsNoTracking().ToList();

// ✅ GOOD: Read-only endpoints use no-tracking
[HttpGet]
public IActionResult GetUsers() {
    return Ok(context.Users.AsNoTracking());
}
```

**Implementation:**
- Detect GET/read-only endpoints without AsNoTracking()
- Suggest AsNoTracking() for performance
- Detect unnecessary tracking in reporting queries

---

## Phase B: ASP.NET Core Middleware Security (KSI-SVC-07)

### 4. Security Headers Validation 🛡️ ENHANCED
**Current:** Basic UseHttpsRedirection check
**Enhanced:** Comprehensive security headers

**Detection Patterns:**
```csharp
// ❌ MISSING: Critical security headers
app.UseHttpsRedirection();
app.UseAuthorization();

// ✅ GOOD: Comprehensive security headers
app.Use(async (context, next) => {
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
    await next();
});

// ✅ BETTER: Use NWebsec middleware
app.UseXContentTypeOptions();
app.UseXfo(options => options.Deny());
app.UseXXssProtection(options => options.EnabledWithBlockMode());
app.UseReferrerPolicy(opts => opts.StrictOriginWhenCrossOrigin());
app.UseCsp(opts => opts.DefaultSources(s => s.Self()));
```

**Implementation:**
- Detect missing X-Content-Type-Options
- Detect missing X-Frame-Options
- Detect missing Content-Security-Policy
- Recommend NWebsec middleware package
- Check for CSP wildcard sources

### 5. Rate Limiting Detection 🚦 NEW
**KSI:** SVC-07 (Secure Coding), AFR-01 (Automated Remediation)

**Detection Patterns:**
```csharp
// ❌ MISSING: No rate limiting on API
[HttpPost]
public IActionResult CreateUser([FromBody] User user) { }

// ✅ GOOD: Built-in rate limiting (.NET 7+)
builder.Services.AddRateLimiter(options => {
    options.AddFixedWindowLimiter("fixed", options => {
        options.PermitLimit = 100;
        options.Window = TimeSpan.FromMinutes(1);
    });
});

[EnableRateLimiting("fixed")]
[HttpPost]
public IActionResult CreateUser([FromBody] User user) { }

// ✅ GOOD: AspNetCoreRateLimit package
services.AddMemoryCache();
services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
services.AddInMemoryRateLimiting();
```

**Implementation:**
- Detect POST/PUT/DELETE endpoints without rate limiting
- Check for AddRateLimiter() configuration
- Check for AspNetCoreRateLimit package
- Recommend per-IP and per-user limits

### 6. Request Size Limits 📏 NEW
**KSI:** SVC-02 (Input Validation), AFR-01 (DoS Protection)

**Detection Patterns:**
```csharp
// ❌ BAD: Unlimited request size (DoS risk)
[HttpPost]
public IActionResult Upload(IFormFile file) { }

// ✅ GOOD: Request size limit
[RequestSizeLimit(10_000_000)] // 10MB
[HttpPost]
public IActionResult Upload(IFormFile file) { }

// ✅ GOOD: Global configuration
builder.Services.Configure<FormOptions>(options => {
    options.MultipartBodyLengthLimit = 10_000_000;
});

builder.Services.Configure<IISServerOptions>(options => {
    options.MaxRequestBodySize = 10_000_000;
});
```

**Implementation:**
- Detect file upload endpoints without [RequestSizeLimit]
- Check for FormOptions.MultipartBodyLengthLimit configuration
- Recommend appropriate limits based on endpoint type

---

## Phase C: Azure Integration Best Practices

### 7. Azure Cosmos DB Security 🌐 NEW
**KSI:** SVC-06 (Secrets), IAM-02 (Service Accounts)

**Detection Patterns:**
```csharp
// ❌ BAD: Hardcoded connection string
var client = new CosmosClient("AccountEndpoint=https://...;AccountKey=...");

// ❌ BAD: Connection string from config (still not ideal)
var connectionString = Configuration["CosmosDb:ConnectionString"];
var client = new CosmosClient(connectionString);

// ✅ GOOD: Managed Identity
var credential = new DefaultAzureCredential();
var client = new CosmosClient(endpoint, credential);

// ✅ GOOD: Key Vault reference in config
// appsettings.json: "@Microsoft.KeyVault(SecretUri=https://...)"
```

**Implementation:**
- Detect CosmosClient with hardcoded connection strings
- Detect AccountKey in code or config
- Recommend DefaultAzureCredential pattern
- Suggest Key Vault configuration provider

### 8. Azure Service Bus Security 📨 NEW
**KSI:** SVC-06 (Secrets), IAM-02, CNA-07 (Service Mesh)

**Detection Patterns:**
```csharp
// ❌ BAD: Connection string authentication
var client = new ServiceBusClient(connectionString);

// ✅ GOOD: Managed Identity
var credential = new DefaultAzureCredential();
var client = new ServiceBusClient(fullyQualifiedNamespace, credential);

// ✅ GOOD: RBAC with specific roles
// "Azure Service Bus Data Sender" role
// "Azure Service Bus Data Receiver" role
```

**Implementation:**
- Detect ServiceBusClient with connection strings
- Recommend Managed Identity authentication
- Suggest RBAC role assignments

### 9. Azure Storage Security 💾 ENHANCED
**Current:** Basic Key Vault checks
**Enhanced:** Storage-specific patterns

**Detection Patterns:**
```csharp
// ❌ BAD: Account key authentication
var client = new BlobServiceClient(connectionString);

// ❌ BAD: Shared Access Signature in code
var sasUri = new Uri("https://...?sv=2021-06-08&ss=b&...");

// ✅ GOOD: Managed Identity with DefaultAzureCredential
var credential = new DefaultAzureCredential();
var client = new BlobServiceClient(new Uri(endpoint), credential);

// ✅ GOOD: User delegation SAS (created from Managed Identity)
var userDelegationKey = await blobServiceClient.GetUserDelegationKeyAsync(...);
var sasBuilder = new BlobSasBuilder(...);
var sasUri = sasBuilder.ToSasQueryParameters(userDelegationKey, accountName);
```

**Implementation:**
- Detect BlobServiceClient/BlobContainerClient with connection strings
- Detect hardcoded SAS tokens
- Recommend DefaultAzureCredential
- Suggest user delegation SAS over account SAS

---

## Phase D: Advanced Validation Patterns (KSI-SVC-02)

### 10. Complex FluentValidation Scenarios 🔍 ENHANCED
**Current:** Basic AbstractValidator detection
**Enhanced:** Advanced validation patterns

**Detection Patterns:**
```csharp
// ❌ MEDIUM: Missing async validation
public class UserValidator : AbstractValidator<User> {
    public UserValidator() {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        // Missing: Check if email exists in database
    }
}

// ✅ GOOD: Async validation with MustAsync
public class UserValidator : AbstractValidator<User> {
    private readonly IUserRepository _repository;
    
    public UserValidator(IUserRepository repository) {
        _repository = repository;
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .MustAsync(async (email, cancellation) => {
                return !await _repository.EmailExistsAsync(email);
            }).WithMessage("Email already in use");
    }
}

// ✅ GOOD: Custom validators with business logic
public class CreateOrderValidator : AbstractValidator<CreateOrderRequest> {
    public CreateOrderValidator(IInventoryService inventory) {
        RuleFor(x => x.ProductId)
            .NotEmpty()
            .MustAsync(async (id, ct) => await inventory.IsAvailableAsync(id))
            .WithMessage("Product not available");
        
        RuleFor(x => x.Quantity)
            .GreaterThan(0)
            .LessThanOrEqualTo(100)
            .When(x => x.IsWholesale == false);
    }
}
```

**Implementation:**
- Detect validators without MustAsync for database checks
- Suggest async validation for I/O operations
- Recommend When() clauses for conditional validation

### 11. Model Binding Security 🔒 ENHANCED
**Current:** Basic ModelState.IsValid check
**Enhanced:** Binding attribute security

**Detection Patterns:**
```csharp
// ❌ BAD: Over-posting vulnerability
[HttpPost]
public IActionResult CreateUser([FromBody] User user) {
    // Attacker can set user.IsAdmin = true
    _db.Users.Add(user);
}

// ✅ GOOD: DTO with explicit binding
public class CreateUserRequest {
    [Required]
    public string Username { get; set; }
    [Required]
    public string Email { get; set; }
    // IsAdmin NOT included - prevents over-posting
}

[HttpPost]
public IActionResult CreateUser([FromBody] CreateUserRequest request) {
    var user = new User {
        Username = request.Username,
        Email = request.Email,
        IsAdmin = false // Set explicitly
    };
}

// ✅ GOOD: [Bind] attribute
[HttpPost]
public IActionResult CreateUser([Bind("Username,Email")] User user) {
    // Only binds specified properties
}
```

**Implementation:**
- Detect entity types bound directly in controllers
- Suggest DTO pattern for input
- Warn about mass assignment vulnerabilities
- Recommend [Bind] or AutoMapper

---

## Phase E: Caching and Performance Security

### 12. Distributed Cache Security 📦 NEW
**KSI:** SVC-06 (Secrets), PIY-02 (PII)

**Detection Patterns:**
```csharp
// ❌ BAD: Caching sensitive data without encryption
await cache.SetStringAsync("user:token:" + userId, authToken);

// ❌ BAD: PII in cache keys (logs show key names)
await cache.SetStringAsync($"user:ssn:{ssn}", userData);

// ✅ GOOD: Encrypt sensitive data before caching
var encryptedToken = _dataProtector.Protect(authToken);
await cache.SetStringAsync($"user:token:{userId}", encryptedToken);

// ✅ GOOD: Hash PII in cache keys
var hashedKey = HashFunction($"user:ssn:{ssn}");
await cache.SetStringAsync(hashedKey, userData);

// ✅ GOOD: Short expiration for sensitive data
var options = new DistributedCacheEntryOptions {
    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
};
await cache.SetStringAsync(key, encryptedValue, options);
```

**Implementation:**
- Detect SetStringAsync with sensitive data patterns
- Check for PII in cache key strings
- Recommend IDataProtector for encryption
- Suggest appropriate expiration times

### 13. Response Caching Validation 🚀 NEW
**KSI:** SVC-07 (Secure Coding), PIY-02 (PII)

**Detection Patterns:**
```csharp
// ❌ BAD: Caching user-specific data
[ResponseCache(Duration = 3600)]
[HttpGet("profile")]
public IActionResult GetUserProfile() {
    // Different users would see cached version!
    return Ok(_userService.GetCurrentUserProfile());
}

// ✅ GOOD: VaryByQueryKeys for personalization
[ResponseCache(Duration = 60, VaryByQueryKeys = new[] { "userId" })]
[HttpGet("profile")]
public IActionResult GetUserProfile([FromQuery] string userId) {
    return Ok(_userService.GetProfile(userId));
}

// ✅ GOOD: No caching for sensitive endpoints
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[HttpGet("transactions")]
public IActionResult GetTransactions() {
    return Ok(_userService.GetTransactions());
}
```

**Implementation:**
- Detect [ResponseCache] on authenticated endpoints
- Check for VaryBy parameters on personalized data
- Recommend NoStore for sensitive data
- Warn about PII in cached responses

---

## Phase F: Async/Await Best Practices

### 14. Async/Await Anti-Patterns 🔄 NEW
**KSI:** SVC-01 (Error Handling), MLA-06 (Performance)

**Detection Patterns:**
```csharp
// ❌ BAD: Sync over async (deadlock risk)
public void ProcessUser(int userId) {
    var user = _repository.GetUserAsync(userId).Result; // Deadlock!
}

// ❌ BAD: Async void (no exception handling)
public async void DeleteUser(int userId) {
    await _repository.DeleteAsync(userId); // Exceptions not catchable!
}

// ❌ BAD: Missing ConfigureAwait in libraries
public async Task<User> GetUserAsync(int id) {
    return await _db.Users.FindAsync(id); // Captures context unnecessarily
}

// ✅ GOOD: Proper async all the way
public async Task ProcessUserAsync(int userId) {
    var user = await _repository.GetUserAsync(userId);
}

// ✅ GOOD: Async Task (not void)
public async Task DeleteUserAsync(int userId) {
    await _repository.DeleteAsync(userId);
}

// ✅ GOOD: ConfigureAwait(false) in libraries
public async Task<User> GetUserAsync(int id) {
    return await _db.Users.FindAsync(id).ConfigureAwait(false);
}
```

**Implementation:**
- Detect .Result or .Wait() on Task
- Detect async void methods (except event handlers)
- Suggest ConfigureAwait(false) for library code
- Recommend async all the way pattern

---

## Implementation Priority

**Week 1: High Impact (P0)**
1. ✅ Entity Framework SQL Injection (Phase A.1)
2. ✅ Security Headers Validation (Phase B.4)
3. ✅ Azure Service Authentication (Phase C.7-9)
4. ✅ Model Binding Security (Phase D.11)

**Week 2: Performance & Cache (P1)**
5. ✅ EF N+1 Detection (Phase A.2)
6. ✅ Rate Limiting (Phase B.5)
7. ✅ Distributed Cache Security (Phase E.12)
8. ✅ Async/Await Patterns (Phase F.14)

**Week 3: Advanced (P2)**
9. ✅ EF Tracking Optimization (Phase A.3)
10. ✅ Request Size Limits (Phase B.6)
11. ✅ Response Caching (Phase E.13)
12. ✅ Advanced FluentValidation (Phase D.10)

---

## Success Metrics

**Quality Improvements:**
- ✅ Reduce false positives by 20%+ (better Azure integration detection)
- ✅ Catch 15+ new vulnerability patterns (EF, caching, async)
- ✅ Provide Azure-specific remediation guidance
- ✅ Improve security best practice recommendations

**Coverage Improvements:**
- ✅ Deeper analysis of existing 28 KSIs
- ✅ Better alignment with .NET 8 best practices
- ✅ Enhanced Azure-native patterns
- ✅ Production-ready security guidance

**Testing:**
- ✅ Add 24+ new test cases (2 per enhancement)
- ✅ All tests passing with existing suite
- ✅ No regressions in existing checks

---

## Documentation Updates Required

1. ✅ Update copilot-instructions.md with new patterns
2. ✅ Update TESTING.md with test coverage
3. ✅ Add inline code examples for each pattern
4. ✅ Update README with enhanced capabilities
5. ✅ Create migration guide for teams upgrading

---

## Next Steps

1. ✅ Review and approve enhancement plan
2. ✅ Start with Week 1 high-impact enhancements
3. ✅ Test each enhancement thoroughly
4. ✅ Commit incrementally with clear messages
5. ✅ Update documentation alongside code changes

Would you like me to start implementing these enhancements?
