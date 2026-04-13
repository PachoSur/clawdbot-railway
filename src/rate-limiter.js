/**
 * Token-based rate limiter para OpenClaw
 * 
 * Previene exceder el límite de 30k tokens/minuto de Anthropic
 * usando estimaciones conservadoras de tokens por request
 */

export class TokenRateLimiter {
  constructor(maxTokensPerMinute = 25000) {
    this.maxTokensPerMinute = maxTokensPerMinute;
    this.buckets = new Map(); // user_id -> { tokens, resetAt }
    
    // Limpiar buckets cada minuto
    setInterval(() => this.cleanup(), 60000);
  }

  /**
   * Estima tokens basado en el tipo de request
   * Estos son números conservadores
   */
  estimateTokens(req) {
    // Requests WebSocket (Telegram, canales) = heavy
    if (req.headers.upgrade === 'websocket') {
      return 2000; // Contexto completo de canal
    }

    // POST con payload grande
    if (req.method === 'POST' && req.body) {
      const bodyStr = JSON.stringify(req.body);
      if (bodyStr.length > 5000) return 2000;
      if (bodyStr.length > 2000) return 1500;
      return 1000;
    }

    // GET requests
    if (req.method === 'GET') return 500;

    // Default
    return 1000;
  }

  /**
   * Obtiene o crea el bucket para este usuario/sesión
   */
  getBucket(identifier) {
    const now = Date.now();
    if (!this.buckets.has(identifier)) {
      this.buckets.set(identifier, { tokens: 0, resetAt: now + 60000 });
    }

    const bucket = this.buckets.get(identifier);
    
    // Reset si pasó el minuto
    if (now >= bucket.resetAt) {
      bucket.tokens = 0;
      bucket.resetAt = now + 60000;
    }

    return bucket;
  }

  /**
   * Verifica si se puede hacer un request
   * Retorna { allowed: boolean, tokensRemaining: number, retryAfter: number }
   */
  checkLimit(req) {
    const identifier = this.getIdentifier(req);
    const estimatedTokens = this.estimateTokens(req);
    const bucket = this.getBucket(identifier);
    
    const tokensRemaining = this.maxTokensPerMinute - bucket.tokens;
    const allowed = estimatedTokens <= tokensRemaining;

    if (allowed) {
      bucket.tokens += estimatedTokens;
    }

    const retryAfter = Math.ceil((bucket.resetAt - Date.now()) / 1000);

    return {
      allowed,
      estimatedTokens,
      tokensUsed: bucket.tokens,
      tokensRemaining: Math.max(0, tokensRemaining - estimatedTokens),
      retryAfter: retryAfter > 0 ? retryAfter : 0,
    };
  }

  /**
   * Obtiene un identificador único por usuario/sesión
   */
  getIdentifier(req) {
    // Telegram user ID si está en el path
    const telegramMatch = req.path.match(/telegram[:/](\d+)/);
    if (telegramMatch) return `telegram:${telegramMatch[1]}`;

    // IP del cliente (para agrupar requests)
    return req.ip || req.connection.remoteAddress || 'unknown';
  }

  /**
   * Limpia buckets expirados
   */
  cleanup() {
    const now = Date.now();
    for (const [id, bucket] of this.buckets.entries()) {
      if (now > bucket.resetAt + 120000) {
        this.buckets.delete(id);
      }
    }
  }

  /**
   * Obtiene estadísticas (para debugging)
   */
  getStats() {
    const stats = {};
    for (const [id, bucket] of this.buckets.entries()) {
      stats[id] = {
        tokens: bucket.tokens,
        resetIn: Math.max(0, bucket.resetAt - Date.now()),
      };
    }
    return stats;
  }
}

/**
 * Middleware Express para rechazar requests que excedan el límite
 */
export function createRateLimitMiddleware(limiter) {
  return (req, res, next) => {
    // No limitar /healthz ni /setup/healthz
    if (req.path === '/healthz' || req.path === '/setup/healthz') {
      return next();
    }

    // No limitar webhooks externos (Telegram callbacks)
    if (req.path.startsWith('/hooks')) {
      return next();
    }

    const check = limiter.checkLimit(req);

    // Agregar headers informativos
    res.set('X-Token-Limit-Used', check.tokensUsed);
    res.set('X-Token-Limit-Remaining', check.tokensRemaining);
    res.set('X-Token-Limit-Reset', new Date(Date.now() + check.retryAfter * 1000).toISOString());

    if (!check.allowed) {
      console.warn(
        `[rate-limiter] Blocked request from ${limiter.getIdentifier(req)}. ` +
        `Would use ${check.estimatedTokens} tokens, only ${check.tokensRemaining} available. ` +
        `Retry in ${check.retryAfter}s`
      );

      return res.status(429).json({
        ok: false,
        error: 'Token rate limit exceeded',
        message: `Currently using ${check.tokensUsed}/${limiter.maxTokensPerMinute} tokens/min. ` +
                 `This request would use ~${check.estimatedTokens} tokens.`,
        tokensRemaining: check.tokensRemaining,
        retryAfter: check.retryAfter,
      });
    }

    next();
  };
}
