# Security Policy

Openport is developed by iTech (VAT BE 0643.553.428), Belgium. We take security
reports seriously and are committed to working with researchers who report
issues to us in good faith.

## Reporting a Vulnerability

**Email: security@openport.io**

Please do **not** open a public issue, post in the support chat, or disclose the
issue publicly before we have had a chance to respond. Public disclosure of an
unpatched vulnerability puts our users at risk.

If you would like to encrypt your report, request our PGP key at the address
above and we will provide it before you send details.

### What to include

The more of this you can provide, the faster we can triage:

- A description of the issue and its impact
- The affected component (see Scope below) and version
- Steps to reproduce, ideally a minimal proof of concept
- Any logs, requests, or output that demonstrate the issue
- Whether you believe the issue is being actively exploited
- How you would like to be credited, if at all

### What to expect from us

| Stage | Target |
|---|---|
| Acknowledgement of your report | Within 5 business days |
| Initial assessment and severity rating | Within 10 business days |
| Fix for critical severity issues | Within 30 days of triage |
| Fix for high severity issues | Within 90 days of triage |

We will keep you informed as we work through the issue, tell you when a fix is
released, and credit you in the release notes unless you prefer otherwise.

These are targets rather than guarantees — a complex issue may take longer. If
it does, we will tell you why rather than going quiet.

### Coordinated disclosure

We ask for a 90-day disclosure window from the date we acknowledge your report,
extended by mutual agreement if a fix is genuinely complex. We will not take
legal action against researchers who:

- Act in good faith and follow this policy
- Avoid privacy violations, data destruction, and service degradation
- Only interact with accounts they own or have explicit permission to test
- Give us reasonable time to remediate before public disclosure

## Scope

This policy covers:

| Component | Repository |
|---|---|
| Openport server and web application | `openport-server` |
| Openport client | `openport-go-client` |
| Packaging and distribution | `openport-distribution` |
| Documentation | `openport-docs` |
| The openport.io service | — |

Out of scope: denial of service through volumetric traffic, social engineering
of our staff or users, findings from automated scanners without a demonstrated
exploit path, and issues in third-party services we do not control.

Note that Openport's purpose is to expose local services to the internet. A
tunnel making a user's own service reachable is intended behaviour, not a
vulnerability. Issues that let one user reach *another* user's tunnel, session,
or account are very much in scope.

## Supported Versions

Security fixes are provided for the latest released version. We recommend
always running the current release.

> A formal support period, as required by Article 13(8) of the EU Cyber
> Resilience Act, is being defined and will be published here. Until then, treat
> "latest release" as the supported version.

## Regulatory reporting

As a manufacturer placing a product with digital elements on the EU market, we
report actively exploited vulnerabilities and severe security incidents to ENISA
and to the Belgian Centre for Cybersecurity (CCB) as required by Article 14 of
the EU Cyber Resilience Act.

If you report an actively exploited vulnerability to us, please say so
explicitly — it triggers a 24-hour regulatory notification clock on our side.
