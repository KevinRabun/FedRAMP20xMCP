"""
Test KSI-CNA-05 AST Conversion - Rate Limiting / DoS Protection

Tests AST-based TypeScript analysis for:
- Express apps without express-rate-limit
- NestJS apps without @nestjs/throttler

Ref: KSI-CNA-05 (Unwanted Activity / DoS Protection)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_05 import KSI_CNA_05_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_typescript_express_without_rate_limit():
    """Test TypeScript AST detects Express app without rate limiting."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import express from 'express';

// INSECURE: No rate limiting
const app = express();

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
});

app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) == 1, f"Expected 1 rate limiting finding, got {len(rate_limit_findings)}"
    assert rate_limit_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript Express without rate limit detected via AST")


def test_typescript_express_with_rate_limit_passes():
    """Test TypeScript AST passes Express app with rate limiting."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import express from 'express';
import rateLimit from 'express-rate-limit';

const app = express();

// SECURE: Rate limiting configured
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    standardHeaders: true
});

app.use(limiter);

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
});

app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) == 0, f"Expected 0 rate limiting findings, got {len(rate_limit_findings)}"
    print("[PASS] TypeScript Express with rate limit passes via AST")


def test_typescript_nestjs_without_throttler():
    """Test TypeScript AST detects NestJS app without throttler."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import { Module, Controller, Get } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

// INSECURE: No throttler module
@Module({
    imports: [],
    controllers: [AppController],
})
export class AppModule {}

@Controller('api')
export class AppController {
    @Get('data')
    getData() {
        return { data: 'sensitive' };
    }
}

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    await app.listen(3000);
}
bootstrap();
"""
    findings = analyzer.analyze_typescript(code, "main.ts")
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) >= 1, f"Expected at least 1 rate limiting finding, got {len(rate_limit_findings)}"
    assert rate_limit_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript NestJS without throttler detected via AST")


def test_typescript_nestjs_with_throttler_passes():
    """Test TypeScript AST passes NestJS app with throttler."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import { Module, Controller, Get } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ThrottlerModule, Throttle } from '@nestjs/throttler';

// SECURE: Throttler module configured
@Module({
    imports: [
        ThrottlerModule.forRoot({
            ttl: 60,
            limit: 100,
        }),
    ],
    controllers: [AppController],
})
export class AppModule {}

@Controller('api')
export class AppController {
    @Get('data')
    @Throttle(10, 60)
    getData() {
        return { data: 'sensitive' };
    }
}

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    await app.listen(3000);
}
bootstrap();
"""
    findings = analyzer.analyze_typescript(code, "main.ts")
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) == 0, f"Expected 0 rate limiting findings, got {len(rate_limit_findings)}"
    print("[PASS] TypeScript NestJS with throttler passes via AST")


def test_typescript_express_multiple_middlewares():
    """Test TypeScript AST detects Express with other middlewares but no rate limit."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app = express();

// INSECURE: Has security middlewares but NO rate limiting
app.use(cors());
app.use(helmet());
app.use(express.json());

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
});

app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) == 1, f"Expected 1 rate limiting finding, got {len(rate_limit_findings)}"
    print("[PASS] TypeScript Express with other middlewares but no rate limit detected via AST")


def test_typescript_express_with_custom_rate_limiter():
    """Test TypeScript AST passes Express with custom rate limiter."""
    analyzer = KSI_CNA_05_Analyzer()
    code = """
import express from 'express';
import { RateLimiterMiddleware } from './custom-rate-limiter';

const app = express();

// SECURE: Custom rate limiter
const rateLimiter = new RateLimiterMiddleware({
    windowMs: 60000,
    max: 100
});

app.use(rateLimiter.middleware());

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
});

app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    
    rate_limit_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_limit_findings) == 0, f"Expected 0 rate limiting findings, got {len(rate_limit_findings)}"
    print("[PASS] TypeScript Express with custom rate limiter passes via AST")


if __name__ == "__main__":
    print("=== Testing KSI-CNA-05 TypeScript AST Conversion ===\n")
    
    print("Express Tests:")
    test_typescript_express_without_rate_limit()
    test_typescript_express_with_rate_limit_passes()
    test_typescript_express_multiple_middlewares()
    test_typescript_express_with_custom_rate_limiter()
    
    print("\nNestJS Tests:")
    test_typescript_nestjs_without_throttler()
    test_typescript_nestjs_with_throttler_passes()
    
    print("\n" + "="*70)
    print("ALL 6 CNA-05 TYPESCRIPT TESTS PASSED [PASS]")
    print("Progress: 16/17 analyzers complete (94.1%)")
    print("="*70)
