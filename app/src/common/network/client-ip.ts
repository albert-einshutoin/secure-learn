import { Request } from 'express';

export function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const rawIp =
    typeof forwarded === 'string'
      ? forwarded.split(',')[0].trim()
      : req.socket.remoteAddress || 'unknown';

  // Fail2ban needs a routable IP token. Node often reports Docker IPv4 clients
  // as IPv6-mapped addresses, so normalize them before writing security logs.
  return rawIp.startsWith('::ffff:') ? rawIp.slice('::ffff:'.length) : rawIp;
}
