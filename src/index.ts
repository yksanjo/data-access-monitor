/**
 * Data Access Monitor
 * 
 * Standalone library for monitoring and controlling access to sensitive data resources.
 */

export type ThreatLevel = 1 | 2 | 3 | 4;

export interface AccessPolicy {
  resource: string | RegExp;
  allowedAccessTypes: string[];
  requireApproval: boolean;
  maxRequestsPerMinute?: number;
  sensitive?: boolean;
}

export interface DataAccessRequest {
  accessType: 'read' | 'write' | 'delete' | 'execute';
  resource: string;
  userId?: string;
  metadata?: Record<string, any>;
}

export interface DataAccessResult {
  allowed: boolean;
  threatLevel: ThreatLevel;
  reason: string;
}

export class DataAccessMonitor {
  private accessPolicies: Map<string, AccessPolicy>;
  private accessLog: Array<{
    timestamp: string;
    request: DataAccessRequest;
    result: DataAccessResult;
  }>;
  private rateLimitMap: Map<string, { count: number; resetTime: number }>;

  constructor() {
    this.accessPolicies = new Map();
    this.accessLog = [];
    this.rateLimitMap = new Map();
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default access policies
   */
  private initializeDefaultPolicies(): void {
    this.addPolicy({
      resource: /^(user|sensitive|private)_data/i,
      allowedAccessTypes: ['read'],
      requireApproval: true,
      sensitive: true
    });

    this.addPolicy({
      resource: /^(config|system|admin)_/i,
      allowedAccessTypes: ['read'],
      requireApproval: true,
      sensitive: true
    });

    this.addPolicy({
      resource: /database/i,
      allowedAccessTypes: ['read', 'write'],
      requireApproval: false,
      maxRequestsPerMinute: 100
    });

    this.addPolicy({
      resource: /api[_-]?key|secret|password|token/i,
      allowedAccessTypes: [],
      requireApproval: true,
      sensitive: true
    });

    this.addPolicy({
      resource: /.*/,
      allowedAccessTypes: ['read'],
      requireApproval: false
    });
  }

  /**
   * Add an access policy
   */
  addPolicy(policy: AccessPolicy): void {
    const key = policy.resource instanceof RegExp 
      ? policy.resource.source 
      : policy.resource;
    this.accessPolicies.set(key, policy);
  }

  /**
   * Check if access should be allowed
   */
  checkAccess(
    accessType: string,
    resource: string,
    userId?: string,
    metadata?: Record<string, any>
  ): DataAccessResult {
    const request: DataAccessRequest = {
      accessType: accessType as 'read' | 'write' | 'delete' | 'execute',
      resource,
      userId,
      metadata
    };

    // Check rate limiting
    const rateLimitResult = this.checkRateLimit(resource, userId);
    if (!rateLimitResult.allowed) {
      return this.logAndReturn(request, rateLimitResult);
    }

    // Find matching policy
    const policy = this.findMatchingPolicy(resource);
    
    if (!policy) {
      return this.logAndReturn(request, {
        allowed: false,
        threatLevel: 3,
        reason: 'No matching policy found'
      });
    }

    // Check if access type is allowed
    if (!policy.allowedAccessTypes.includes(accessType)) {
      return this.logAndReturn(request, {
        allowed: false,
        threatLevel: 2,
        reason: `Access type '${accessType}' not allowed for this resource`
      });
    }

    // Check for sensitive resource access
    if (policy.sensitive) {
      const sensitivityCheck = this.checkSensitiveAccess(request);
      if (!sensitivityCheck.allowed) {
        return this.logAndReturn(request, sensitivityCheck);
      }
    }

    // Check for anomalous access patterns
    const anomalyResult = this.checkAnomalousAccess(resource, userId);
    if (!anomalyResult.allowed) {
      return this.logAndReturn(request, anomalyResult);
    }

    // Check if approval is required
    if (policy.requireApproval && !metadata?.approved) {
      return this.logAndReturn(request, {
        allowed: false,
        threatLevel: 2,
        reason: 'Access requires approval'
      });
    }

    return this.logAndReturn(request, {
      allowed: true,
      threatLevel: 1,
      reason: 'Access granted'
    });
  }

  /**
   * Check rate limits
   */
  private checkRateLimit(resource: string, userId?: string): DataAccessResult {
    const key = `${resource}:${userId || 'anonymous'}`;
    const now = Date.now();
    const limit = this.rateLimitMap.get(key);

    if (!limit) {
      this.rateLimitMap.set(key, {
        count: 1,
        resetTime: now + 60000
      });
      return { allowed: true, threatLevel: 1, reason: 'OK' };
    }

    if (now > limit.resetTime) {
      this.rateLimitMap.set(key, {
        count: 1,
        resetTime: now + 60000
      });
      return { allowed: true, threatLevel: 1, reason: 'OK' };
    }

    if (limit.count >= 60) {
      return {
        allowed: false,
        threatLevel: 3,
        reason: 'Rate limit exceeded'
      };
    }

    limit.count++;
    return { allowed: true, threatLevel: 1, reason: 'OK' };
  }

  /**
   * Find matching policy for a resource
   */
  private findMatchingPolicy(resource: string): AccessPolicy | null {
    if (this.accessPolicies.has(resource)) {
      return this.accessPolicies.get(resource)!;
    }

    for (const [, policy] of this.accessPolicies) {
      if (policy.resource instanceof RegExp) {
        if (policy.resource.test(resource)) {
          return policy;
        }
      }
    }

    return null;
  }

  /**
   * Check sensitive data access
   */
  private checkSensitiveAccess(request: DataAccessRequest): DataAccessResult {
    const sensitivePatterns = [
      /api[_-]?key/i,
      /secret/i,
      /password/i,
      /token/i,
      /credential/i,
      /private[_-]?key/i,
      /ssn/i,
      /credit[_-]?card/i,
      /social[_-]?security/i
    ];

    for (const pattern of sensitivePatterns) {
      if (pattern.test(request.resource)) {
        if (request.accessType === 'write' || request.accessType === 'delete') {
          return {
            allowed: false,
            threatLevel: 4,
            reason: 'Write/delete access to sensitive resource blocked'
          };
        }

        return {
          allowed: true,
          threatLevel: 2,
          reason: 'Sensitive resource access logged'
        };
      }
    }

    return { allowed: true, threatLevel: 1, reason: 'OK' };
  }

  /**
   * Check for anomalous access patterns
   */
  private checkAnomalousAccess(resource: string, userId?: string): DataAccessResult {
    const recentAccesses = this.accessLog.filter(log => {
      const logTime = new Date(log.timestamp).getTime();
      const now = Date.now();
      return log.request.resource === resource &&
             log.request.userId === userId &&
             now - logTime < 60000;
    });

    if (recentAccesses.length > 50) {
      return {
        allowed: true,
        threatLevel: 3,
        reason: 'Unusual access volume detected - flagged for review'
      };
    }

    const uniqueResources = new Set(
      this.accessLog
        .filter(log => log.request.userId === userId)
        .slice(-20)
        .map(log => log.request.resource)
    );

    if (uniqueResources.size > 15) {
      return {
        allowed: true,
        threatLevel: 3,
        reason: 'Potential resource enumeration detected'
      };
    }

    return { allowed: true, threatLevel: 1, reason: 'OK' };
  }

  /**
   * Log access and return result
   */
  private logAndReturn(
    request: DataAccessRequest,
    result: DataAccessResult
  ): DataAccessResult {
    this.accessLog.push({
      timestamp: new Date().toISOString(),
      request,
      result
    });

    if (this.accessLog.length > 10000) {
      this.accessLog.splice(0, 5000);
    }

    return result;
  }

  /**
   * Get access logs
   */
  getLogs(limit: number = 100): typeof this.accessLog {
    return this.accessLog.slice(-limit);
  }

  /**
   * Get access statistics
   */
  getStats(): {
    totalRequests: number;
    blockedRequests: number;
    sensitiveAccesses: number;
    uniqueResources: number;
    uniqueUsers: number;
  } {
    const blocked = this.accessLog.filter(l => !l.result.allowed).length;
    const sensitive = this.accessLog.filter(l => l.request.resource.includes('sensitive')).length;
    const resources = new Set(this.accessLog.map(l => l.request.resource));
    const users = new Set(this.accessLog.map(l => l.request.userId).filter(Boolean));

    return {
      totalRequests: this.accessLog.length,
      blockedRequests: blocked,
      sensitiveAccesses: sensitive,
      uniqueResources: resources.size,
      uniqueUsers: users.size
    };
  }

  /**
   * Clear old logs
   */
  clearLogs(olderThanMs: number = 3600000): void {
    const cutoff = Date.now() - olderThanMs;
    this.accessLog = this.accessLog.filter(log => 
      new Date(log.timestamp).getTime() > cutoff
    );
  }
}

export default DataAccessMonitor;
