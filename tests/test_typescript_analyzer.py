#!/usr/bin/env python3
"""
Comprehensive tests for TypeScriptAnalyzer.

Tests cover all security checks for TypeScript/JavaScript applications including:
- Authentication (KSI-IAM-01)
- Secrets management (KSI-SVC-06)
- Dependency security (KSI-SVC-01, KSI-SVC-02)
- PII handling (KSI-PIY-02)
- Logging and monitoring (KSI-MLA-05, KSI-MLA-07)
- Input validation (KSI-SVC-03)
- Authorization (KSI-IAM-02, KSI-IAM-04, KSI-IAM-07)
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.typescript_analyzer import TypeScriptAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_hardcoded_secrets_detection():
    """Test detection of hardcoded secrets in TypeScript/JavaScript code."""
    code = '''
    export class Config {
        private static readonly API_KEY = "sk-1234567890abcdef";
        private connectionString = "Server=tcp:myserver.database.windows.net;Database=mydb;User ID=admin;Password=MyP@ssw0rd123!;";
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "config.ts")
    
    assert len(result.findings) >= 1
    assert any("secret" in f.description.lower() or "password" in f.description.lower() for f in result.findings)
    print("✓ Hardcoded secrets detection test passed")


def test_jwt_authentication():
    """Test detection of authentication with JWT middleware."""
    code = '''
    import { Request, Response, NextFunction } from 'express';
    import jwt from 'jsonwebtoken';
    
    export const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!);
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(403).json({ error: 'Invalid token' });
        }
    };
    
    app.get('/api/secure', authenticateJWT, (req, res) => {
        res.json({ data: 'Secure data' });
    });
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "auth.ts")
    
    # Should have no high severity findings for authentication
    auth_findings = [f for f in result.findings if "authentication" in f.description.lower() or "authentication" in f.title.lower()]
    high_severity_auth = [f for f in auth_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity_auth) == 0 or len(auth_findings) == 0
    print("✓ JWT authentication test passed")


def test_key_vault_usage():
    """Test detection of proper Key Vault usage with DefaultAzureCredential."""
    code = '''
    import { SecretClient } from '@azure/keyvault-secrets';
    import { DefaultAzureCredential } from '@azure/identity';
    
    export class SecretManager {
        private client: SecretClient;
        
        constructor() {
            const keyVaultUrl = process.env.KEY_VAULT_URL!;
            const credential = new DefaultAzureCredential();
            this.client = new SecretClient(keyVaultUrl, credential);
        }
        
        async getSecret(secretName: string): Promise<string> {
            const secret = await this.client.getSecret(secretName);
            return secret.value!;
        }
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "secretManager.ts")
    
    # Should recognize good Key Vault pattern
    secret_findings = [f for f in result.findings if "key vault" in f.description.lower() or "key vault" in f.title.lower()]
    
    # May have informational findings but no high severity
    high_severity = [f for f in secret_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ Key Vault usage test passed")


def test_eval_detection():
    """Test detection of dangerous eval() usage."""
    code = '''
    export function executeUserCode(code: string): any {
        return eval(code);
    }
    
    export function processFormula(formula: string): number {
        const result = eval(formula);
        return result;
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "unsafe.ts")
    
    assert len(result.findings) >= 1
    assert any("eval" in f.description.lower() or "code execution" in f.description.lower() 
               for f in result.findings)
    print("✓ eval() detection test passed")


def test_innerhtml_detection():
    """Test detection of innerHTML and dangerouslySetInnerHTML usage."""
    code = '''
    export function renderComment(comment: string) {
        const div = document.getElementById('comments');
        div.innerHTML = comment;
    }
    
    export const UserComment: React.FC<Props> = ({ comment }) => {
        return <div dangerouslySetInnerHTML={{ __html: comment }} />;
    };
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "comments.tsx")
    
    assert len(result.findings) >= 1
    assert any("innerhtml" in f.description.lower() or "dangerously" in f.description.lower() 
               for f in result.findings)
    print("✓ innerHTML detection test passed")


def test_crypto_encryption():
    """Test detection of proper PII encryption with Node.js crypto."""
    code = '''
    import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
    
    export class PiiEncryption {
        private algorithm = 'aes-256-gcm';
        
        encrypt(data: string, key: Buffer): { encrypted: string; iv: string; tag: string } {
            const iv = randomBytes(16);
            const cipher = createCipheriv(this.algorithm, key, iv);
            
            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const tag = cipher.getAuthTag();
            
            return {
                encrypted,
                iv: iv.toString('hex'),
                tag: tag.toString('hex')
            };
        }
        
        decrypt(encrypted: string, key: Buffer, iv: string, tag: string): string {
            const decipher = createDecipheriv(this.algorithm, key, Buffer.from(iv, 'hex'));
            decipher.setAuthTag(Buffer.from(tag, 'hex'));
            
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        }
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "encryption.ts")
    
    # Should recognize good crypto usage
    pii_findings = [f for f in result.findings if "pii" in f.description.lower() or "encrypt" in f.description.lower()]
    high_severity = [f for f in pii_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Crypto encryption test passed")


def test_winston_logging():
    """Test detection of proper logging with Winston."""
    code = '''
    import winston from 'winston';
    
    export const logger = winston.createLogger({
        level: 'info',
        format: winston.format.json(),
        transports: [
            new winston.transports.Console(),
            new winston.transports.File({ filename: 'error.log', level: 'error' }),
            new winston.transports.File({ filename: 'combined.log' })
        ]
    });
    
    export class OrderService {
        processOrder(order: Order): void {
            logger.info('Processing order', { orderId: order.id });
            
            try {
                // Process order
                logger.info('Order processed successfully', { orderId: order.id });
            } catch (error) {
                logger.error('Error processing order', { orderId: order.id, error });
                throw error;
            }
        }
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "orderService.ts")
    
    # Should recognize proper Winston usage
    logging_findings = [f for f in result.findings if "logging" in f.description.lower() or "logging" in f.title.lower()]
    high_severity = [f for f in logging_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Winston logging test passed")


def test_application_insights():
    """Test detection of Application Insights integration."""
    code = '''
    import * as appInsights from 'applicationinsights';
    
    export class TelemetryService {
        private client: appInsights.TelemetryClient;
        
        constructor() {
            appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
                .setAutoCollectConsole(true)
                .setAutoCollectExceptions(true)
                .start();
            
            this.client = appInsights.defaultClient;
        }
        
        trackEvent(eventName: string, properties?: { [key: string]: string }): void {
            this.client.trackEvent({ name: eventName, properties });
        }
        
        trackException(error: Error): void {
            this.client.trackException({ exception: error });
        }
    }
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "telemetry.ts")
    
    # Should recognize Application Insights usage
    monitoring_findings = [f for f in result.findings if "monitoring" in f.description.lower() or "insights" in f.description.lower()]
    
    # May have recommendations but no high severity issues
    high_severity = [f for f in monitoring_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ Application Insights test passed")


def test_zod_validation():
    """Test detection of input validation with Zod."""
    code = '''
    import { z } from 'zod';
    
    const CreateUserSchema = z.object({
        email: z.string().email(),
        password: z.string().min(8).max(100),
        username: z.string().regex(/^[a-zA-Z0-9_-]{3,20}$/)
    });
    
    export type CreateUserRequest = z.infer<typeof CreateUserSchema>;
    
    app.post('/api/users', (req, res) => {
        try {
            const userData = CreateUserSchema.parse(req.body);
            // Create user
            res.json({ success: true });
        } catch (error) {
            res.status(400).json({ error: 'Invalid input' });
        }
    });
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "userController.ts")
    
    # Should recognize proper validation
    validation_findings = [f for f in result.findings if "validation" in f.description.lower() or "validation" in f.title.lower()]
    high_severity = [f for f in validation_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Zod validation test passed")


def test_secure_session_configuration():
    """Test detection of secure express-session configuration."""
    code = '''
    import session from 'express-session';
    import RedisStore from 'connect-redis';
    
    app.use(session({
        store: new RedisStore({ client: redisClient }),
        secret: process.env.SESSION_SECRET!,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 1800000 // 30 minutes
        }
    }));
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "session.ts")
    
    # Should recognize secure session configuration
    session_findings = [f for f in result.findings if "session" in f.description.lower() or "cookie" in f.description.lower()]
    high_severity = [f for f in session_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Secure session configuration test passed")


def test_authorization_middleware():
    """Test detection of proper authorization middleware."""
    code = '''
    import { Request, Response, NextFunction } from 'express';
    
    export const requireRole = (...roles: string[]) => {
        return (req: Request, res: Response, next: NextFunction) => {
            if (!req.user) {
                return res.status(401).json({ error: 'Not authenticated' });
            }
            
            if (!roles.includes(req.user.role)) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            next();
        };
    };
    
    export const requirePermission = (permission: string) => {
        return (req: Request, res: Response, next: NextFunction) => {
            if (!req.user?.permissions.includes(permission)) {
                return res.status(403).json({ error: 'Permission denied' });
            }
            next();
        };
    };
    
    app.put('/api/documents/:id', requirePermission('edit'), (req, res) => {
        // Update document
    });
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "authorization.ts")
    
    # Should recognize proper authorization
    authz_findings = [f for f in result.findings if "authorization" in f.description.lower() or "authorization" in f.title.lower()]
    high_severity = [f for f in authz_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Authorization middleware test passed")


def test_helmet_usage():
    """Test detection of Helmet.js for security headers."""
    code = '''
    import express from 'express';
    import helmet from 'helmet';
    
    const app = express();
    
    app.use(helmet());
    app.use(helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", 'data:']
        }
    }));
    '''
    
    analyzer = TypeScriptAnalyzer()
    result = analyzer.analyze(code, "app.ts")
    
    # Should recognize Helmet usage
    security_findings = [f for f in result.findings if "helmet" in f.description.lower() or "security headers" in f.description.lower()]
    
    # May have recommendations but no high severity issues
    high_severity = [f for f in security_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ Helmet.js usage test passed")


def run_all_tests():
    """Run all TypeScriptAnalyzer tests."""
    print("\n=== Running TypeScriptAnalyzer Tests ===\n")
    
    test_hardcoded_secrets_detection()
    test_jwt_authentication()
    test_key_vault_usage()
    test_eval_detection()
    test_innerhtml_detection()
    test_crypto_encryption()
    test_winston_logging()
    test_application_insights()
    test_zod_validation()
    test_secure_session_configuration()
    test_authorization_middleware()
    test_helmet_usage()
    
    print("\n=== All TypeScriptAnalyzer Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
