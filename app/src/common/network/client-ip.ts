import { Request } from 'express';
import { isIP } from 'net';

export function getClientIp(req: Request): string {
  // req.ip is resolved by Express using its trust-proxy policy. Reading
  // X-Forwarded-For directly would let an untrusted client bypass lockouts and
  // write arbitrary source addresses into Fail2ban/SIEM evidence.
  const rawIp = req.ip || req.socket.remoteAddress || 'unknown';

  // Fail2ban needs a routable IP token. Node often reports Docker IPv4 clients
  // as IPv6-mapped addresses, so normalize them before writing security logs.
  const normalizedIp = rawIp.startsWith('::ffff:')
    ? rawIp.slice('::ffff:'.length)
    : rawIp;

  return isIP(normalizedIp) ? normalizedIp : 'unknown';
}
