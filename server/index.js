const express = require('express');
const rateLimit = require('express-rate-limit');
const tls = require('tls');
const crypto = require('crypto');
const dns = require('dns').promises;
const dnsLookup = require('dns').lookup;
const path = require('path');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 8105;

app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, '..', 'public')));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a minute and try again.' },
});
app.use('/api/', limiter);

const TLS_TIMEOUT_MS = 6000;
const DNS_TIMEOUT_MS = 4000;

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) return isPrivateIp(lower.replace('::ffff:', ''));
    return false;
  }
  return true;
}

function safeLookup(hostname, options, callback) {
  dnsLookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addresses = Array.isArray(address) ? address : [{ address, family }];
    for (const a of addresses) {
      if (isPrivateIp(a.address || address)) {
        return callback(new Error('Refusing to connect to a private or reserved address'));
      }
    }
    callback(null, address, family);
  });
}

function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  const re = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/;
  return re.test(domain);
}

function normalizeDomain(input) {
  let d = (input || '').trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0];
  d = d.split(':')[0];
  d = d.replace(/\.$/, '');
  return d;
}

function isValidPort(port) {
  return Number.isInteger(port) && port > 0 && port < 65536;
}

function parseSanList(subjectaltname) {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.toLowerCase().startsWith('dns:'))
    .map((s) => s.slice(4).toLowerCase());
}

function hostnameMatches(domain, sanList, cnValue) {
  const names = sanList.length > 0 ? sanList : (cnValue ? [cnValue.toLowerCase()] : []);
  const d = domain.toLowerCase();
  return names.some((name) => {
    if (name === d) return true;
    if (name.startsWith('*.')) {
      const suffix = name.slice(1);
      if (!d.endsWith(suffix)) return false;
      const remainder = d.slice(0, d.length - suffix.length);
      return remainder.length > 0 && !remainder.includes('.');
    }
    return false;
  });
}

function keyInfo(certRaw) {
  try {
    const x509 = new crypto.X509Certificate(certRaw);
    const pub = x509.publicKey;
    const type = pub.asymmetricKeyType;
    const details = pub.asymmetricKeyDetails || {};
    if (type === 'rsa' || type === 'rsa-pss') {
      return { type: 'RSA', size: details.modulusLength || null };
    }
    if (type === 'ec') {
      const curve = details.namedCurve || 'unknown curve';
      const size = curve === 'prime256v1' ? 256 : curve === 'secp384r1' ? 384 : curve === 'secp521r1' ? 521 : null;
      return { type: 'EC (' + curve + ')', size };
    }
    return { type: type ? type.toUpperCase() : 'Unknown', size: null };
  } catch {
    return { type: 'Unknown', size: null };
  }
}

function daysBetween(now, then) {
  return Math.floor((then.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

function buildChain(cert) {
  const chain = [];
  let current = cert;
  const seen = new Set();
  while (current && Object.keys(current).length > 0) {
    const fp = current.fingerprint256 || current.fingerprint;
    if (fp && seen.has(fp)) break;
    if (fp) seen.add(fp);
    chain.push(current);
    if (current.issuerCertificate && current.issuerCertificate !== current) {
      current = current.issuerCertificate;
    } else {
      break;
    }
  }
  return chain;
}

function connectTls(domain, port) {
  return new Promise((resolve) => {
    let settled = false;
    let socket;
    try {
      socket = tls.connect({
        host: domain,
        port,
        servername: domain,
        lookup: safeLookup,
        rejectUnauthorized: false,
        timeout: TLS_TIMEOUT_MS,
      });
    } catch (err) {
      resolve({ error: err.message });
      return;
    }

    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError;
      socket.end();
      resolve({ cert, protocol, cipher, authorized, authorizationError });
    });

    socket.once('timeout', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ error: 'Connection timed out. The host may not be listening on this port, or a firewall is blocking it.' });
    });

    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      resolve({ error: err.message });
    });
  });
}

function gradeResult({ daysRemaining, authorized, authorizationError, protocol, key, hostnameOk, domain }) {
  const details = [];
  let score = 0;
  const max = 100;

  let expiryStatus, expiryMeaning, expiryLabel;
  if (daysRemaining < 0) {
    expiryStatus = 'critical';
    expiryLabel = 'Certificate has expired';
    expiryMeaning = 'This certificate expired ' + Math.abs(daysRemaining) + ' day(s) ago. Browsers will show a hard warning and most will block the page entirely.';
  } else if (daysRemaining <= 14) {
    expiryStatus = 'critical';
    expiryLabel = 'Certificate expires very soon';
    expiryMeaning = 'This certificate expires in ' + daysRemaining + ' day(s). Renew it now, there is very little time left.';
    score += 10;
  } else if (daysRemaining <= 30) {
    expiryStatus = 'warning';
    expiryLabel = 'Certificate expiry approaching';
    expiryMeaning = 'This certificate expires in ' + daysRemaining + ' days. Plan a renewal soon.';
    score += 20;
  } else {
    expiryStatus = 'ok';
    expiryLabel = 'Certificate expiry';
    expiryMeaning = 'This certificate is valid for ' + daysRemaining + ' more days. No action needed.';
    score += 30;
  }
  details.push({ key: 'expiry', label: expiryLabel, status: expiryStatus, meaning: expiryMeaning });

  let trustStatus, trustMeaning;
  if (authorized) {
    trustStatus = 'ok';
    trustMeaning = 'Good. This certificate chains up to a certificate authority that browsers and operating systems trust by default.';
    score += 30;
  } else {
    trustStatus = 'critical';
    trustMeaning = 'Visitors will see a browser warning before they can continue. Reason reported: ' + (authorizationError || 'unknown') + '.';
  }
  details.push({ key: 'trust', label: authorized ? 'Trusted certificate chain' : 'Untrusted certificate chain', status: trustStatus, meaning: trustMeaning });

  let protoStatus, protoMeaning;
  if (protocol === 'TLSv1.3') {
    protoStatus = 'ok';
    protoMeaning = 'Good. TLS 1.3 is the newest version, with older weak ciphers removed entirely.';
    score += 20;
  } else if (protocol === 'TLSv1.2') {
    protoStatus = 'ok';
    protoMeaning = 'Good. TLS 1.2 is still considered secure and widely supported, though TLS 1.3 is a further improvement.';
    score += 20;
  } else if (protocol) {
    protoStatus = 'critical';
    protoMeaning = protocol + ' is an outdated protocol version with known weaknesses. It should be disabled in favor of TLS 1.2 or 1.3.';
  } else {
    protoStatus = 'warning';
    protoMeaning = 'The negotiated protocol version could not be determined.';
    score += 10;
  }
  details.push({ key: 'protocol', label: 'Protocol: ' + (protocol || 'unknown'), status: protoStatus, meaning: protoMeaning });

  let keyStatus, keyMeaning;
  if (key.type === 'RSA' && key.size) {
    if (key.size < 2048) {
      keyStatus = 'critical';
      keyMeaning = 'An RSA key under 2048 bits is considered weak by current standards and should be reissued at 2048 bits or larger.';
    } else {
      keyStatus = 'ok';
      keyMeaning = 'Good. ' + key.size + ' bit RSA meets current minimum recommendations.';
      score += 10;
    }
  } else if (key.type.startsWith('EC')) {
    keyStatus = 'ok';
    keyMeaning = 'Good. Elliptic curve keys at standard curve sizes are considered strong and are faster than RSA at an equivalent security level.';
    score += 10;
  } else {
    keyStatus = 'warning';
    keyMeaning = 'The key type or size could not be determined from this certificate.';
    score += 5;
  }
  details.push({ key: 'keyStrength', label: 'Key: ' + key.type + (key.size ? ' (' + key.size + ' bit)' : ''), status: keyStatus, meaning: keyMeaning });

  let hostStatus, hostMeaning;
  if (hostnameOk) {
    hostStatus = 'ok';
    hostMeaning = 'Good. This certificate explicitly lists ' + domain + ' as a name it is valid for.';
    score += 10;
  } else {
    hostStatus = 'critical';
    hostMeaning = 'This certificate does not list ' + domain + ' in its subject alternative names. Browsers will show a name mismatch warning even if the certificate is otherwise valid.';
  }
  details.push({ key: 'hostname', label: hostnameOk ? 'Certificate covers this domain' : 'Certificate does not cover this domain', status: hostStatus, meaning: hostMeaning });

  const pct = Math.round((score / max) * 100);
  let letter, summary;
  if (pct >= 90) { letter = 'A'; summary = 'Strong. This certificate and connection follow current best practices.'; }
  else if (pct >= 75) { letter = 'B'; summary = 'Good, with a minor gap worth a look.'; }
  else if (pct >= 55) { letter = 'C'; summary = 'Fair. There are a few things worth fixing here.'; }
  else if (pct >= 35) { letter = 'D'; summary = 'Weak. Several important things need attention.'; }
  else { letter = 'F'; summary = 'Poor. This connection has serious problems that need fixing.'; }

  return { letter, pct, summary, details };
}

app.get('/api/check', async (req, res) => {
  const domain = normalizeDomain(req.query.domain);
  const rawPort = req.query.port ? parseInt(req.query.port, 10) : 443;

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Enter a valid domain name, for example example.com' });
  }
  if (!isValidPort(rawPort)) {
    return res.status(400).json({ error: 'Port must be a number between 1 and 65535.' });
  }

  try {
    const resolved = await withTimeout(dns.lookup(domain).catch(() => null), DNS_TIMEOUT_MS, null);
    if (!resolved) {
      return res.status(400).json({ error: 'Could not resolve this domain.' });
    }
    if (isPrivateIp(resolved.address)) {
      return res.status(400).json({ error: 'This domain resolves to a private or reserved address and cannot be checked.' });
    }
  } catch {
    return res.status(400).json({ error: 'Could not resolve this domain.' });
  }

  const result = await connectTls(domain, rawPort);
  if (result.error) {
    return res.status(502).json({ error: result.error });
  }

  const cert = result.cert;
  if (!cert || Object.keys(cert).length === 0) {
    return res.status(502).json({ error: 'No certificate was presented by this host and port.' });
  }

  const validTo = new Date(cert.valid_to);
  const now = new Date();
  const daysRemaining = daysBetween(now, validTo);

  const sanList = parseSanList(cert.subjectaltname);
  const cnValue = cert.subject && cert.subject.CN;
  const hostnameOk = hostnameMatches(domain, sanList, cnValue);

  const key = keyInfo(cert.raw);

  const chain = buildChain(cert).map((c) => ({
    subject: (c.subject && c.subject.CN) || 'Unknown',
    issuer: (c.issuer && c.issuer.CN) || 'Unknown',
    validFrom: c.valid_from,
    validTo: c.valid_to,
  }));

  const grade = gradeResult({
    daysRemaining,
    authorized: result.authorized,
    authorizationError: result.authorizationError || null,
    protocol: result.protocol,
    key,
    hostnameOk,
    domain,
  });

  res.json({
    domain,
    port: rawPort,
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysRemaining,
    sanList,
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    protocol: result.protocol,
    cipher: result.cipher,
    key,
    chain,
    grade,
  });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('cert-check listening on 127.0.0.1:' + PORT);
});
