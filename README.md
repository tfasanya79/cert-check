# cert-check.

An SSL/TLS certificate checker. Enter a domain, and see its certificate expiry countdown, chain of trust, negotiated protocol version, public key strength, and which hostnames it actually covers, all explained in plain English.

Live at: https://timfas.com/cert-check/

## What it does

Enter a domain, optionally with a port other than 443, and the tool connects directly to that host over TLS and reports:

- Days remaining until the certificate expires, or how long ago it expired
- Whether the certificate chains up to a certificate authority that browsers trust by default, or would show a warning
- The negotiated TLS protocol version, for example TLS 1.2 or TLS 1.3
- The public key type and size, for example 2048 bit RSA or a named elliptic curve
- The full list of hostnames the certificate is valid for, and whether the requested domain is actually on that list
- The certificate chain from the leaf certificate up through each issuer

Each finding gets a plain English explanation of what it means and why it matters, plus an overall letter grade summarizing the connection.

## Why this matters

An expired or misconfigured certificate is one of the most common causes of a site going down in production, and it is entirely preventable with a simple check. Beyond expiry, a lot of certificate problems are invisible until a browser flags them: an outdated protocol version, a certificate that does not actually cover the domain being served, or a weak key size. This tool surfaces all of that in one place instead of digging through browser developer tools or command line TLS output by hand.

## Tech stack

A small Express backend connects to the requested host over a raw TLS socket using Node's built in tls and crypto modules to inspect the certificate chain, then a static HTML and JavaScript frontend renders the results. Checks are read only and refuse to connect to private or reserved IP addresses.

## Running it yourself

Requires Node.js 18 or later.

```
npm install
npm start
```

Then open the page served at the configured port.

## Part of a portfolio

This is one of several small, single purpose web tools built for a public portfolio. See the full list at https://timfas.com/