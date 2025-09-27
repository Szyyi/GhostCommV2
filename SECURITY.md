# Security Policy

## Overview

GhostComm is a security-critical application designed for censorship-resistant, surveillance-proof communication. We take security vulnerabilities extremely seriously and commit to rapid, transparent responses to all reported issues.

**Security Contact**: Szymon Procak <SzyYP@proton.me>  
**Response Time**: Within 48 hours  
**Disclosure Timeline**: 90 days responsible disclosure

## Supported Versions

| Version | Protocol | Support Status | Security Updates | End of Life |
| ------- | -------- | -------------- | ---------------- | ----------- |
| 2.1.x   | v2.1     | ✅ Active      | Immediate        | TBD         |
| 2.0.x   | v2.0     | ⚠️ Critical Only | Within 72 hours | March 2025  |
| 1.x.x   | v1.x     | ❌ Deprecated   | None            | January 2025 |

**Note**: Only Protocol v2.1 provides mandatory signature verification. Users on earlier versions should upgrade immediately.

## Security Architecture

GhostComm implements defense-in-depth with multiple security layers:

### Cryptographic Security
- **Ed25519** digital signatures (mandatory in v2.1)
- **X25519** key exchange with Double Ratchet
- **AES-256-GCM** authenticated encryption
- **SHA-256** message chain integrity
- **HMAC-SHA256** for message authentication

### Protocol Security
- Message chain integrity prevents replay attacks
- Sequence number verification detects reordering
- Rate limiting (10 msg/sec) prevents DoS
- Chain break threshold (5) triggers disconnection
- TTL and hop limits prevent infinite propagation

### Implementation Security
- No persistent storage of decrypted messages
- Automatic key rotation every hour
- Public key caching with 1-hour TTL
- Memory cleanup on all error paths
- No logging of message contents

## Threat Model

GhostComm protects against:

### Active Threats
- **Man-in-the-Middle**: Prevented by end-to-end encryption and signature verification
- **Replay Attacks**: Blocked by message chain integrity and sequence numbers
- **Impersonation**: Prevented by Ed25519 signature requirements
- **Message Tampering**: Detected by cryptographic signatures and HMACs
- **Denial of Service**: Mitigated by rate limiting and connection pooling

### Passive Threats
- **Traffic Analysis**: Mitigated by message padding and random delays
- **Device Correlation**: Address rotation every 15 minutes
- **Metadata Leakage**: Minimal metadata, no persistent identifiers
- **Pattern Analysis**: Randomized advertisement intervals

### Out of Scope
- **Physical Device Compromise**: If device is rooted/jailbroken
- **Malicious OS/Firmware**: Compromised operating system
- **Hardware Backdoors**: Radio firmware exploitation
- **Legal Compulsion**: Forced disclosure of keys

## Reporting a Vulnerability

### Where to Report

**Primary Contact**: SzyYP@proton.me  
**PGP Key**: 42d00e9fee2de94ba55f7bf66445fe7ad7ffe560
**Subject Line Format**: `[SECURITY] GhostComm: <brief description>`

### What to Include

1. **Vulnerability Description**
   - Type of vulnerability (e.g., replay attack, key leakage)
   - Affected component (e.g., BLEConnectionManager, Protocol handshake)
   - Protocol version affected

2. **Reproduction Steps**
   - Detailed steps to reproduce
   - Required setup or conditions
   - Success rate (reliable/intermittent)

3. **Impact Assessment**
   - Confidentiality/Integrity/Availability impact
   - Number of users potentially affected
   - Prerequisites for exploitation

4. **Proof of Concept** (if available)
   - Minimal code demonstrating the issue
   - Screenshots or logs (sanitize sensitive data)
   - Test environment details

### Response Timeline

- **Initial Response**: Within 48 hours
- **Severity Assessment**: Within 72 hours
- **Fix Timeline**:
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: Next regular release

### Disclosure Process

1. **Day 0-7**: Initial triage and verification
2. **Day 7-30**: Develop and test fix
3. **Day 30-60**: Beta testing with reporter (if willing)
4. **Day 60-90**: Prepare coordinated disclosure
5. **Day 90**: Public disclosure with credit

## Security Classifications

### Critical (CVSS 9.0-10.0)
- Remote code execution
- Complete key material exposure
- Protocol-level authentication bypass
- Silent message decryption capability

**Response**: Immediate patch, emergency release, user notification

### High (CVSS 7.0-8.9)
- Message chain integrity bypass
- Signature verification skip
- Session hijacking capability
- Partial key leakage

**Response**: Patch within 14 days, security advisory

### Medium (CVSS 4.0-6.9)
- DoS requiring specific conditions
- Information disclosure of metadata
- Relay amplification attacks
- Resource exhaustion

**Response**: Patch within 30 days, release notes mention

### Low (CVSS 0.0-3.9)
- Theoretical attacks requiring physical access
- Performance degradation
- Non-security bugs with minor impact

**Response**: Fix in next regular release

## Recognition Program

Security researchers who report valid vulnerabilities will receive:

- **Credit**: Named acknowledgment in security advisories
- **Early Access**: Beta testing of security fixes
- **Reference Letter**: For significant findings
- **GhostComm Contributor Status**: For critical discoveries

## Security Best Practices for Users

### Operational Security
1. **Verify Devices**: Always verify device fingerprints out-of-band
2. **Regular Updates**: Install updates within 48 hours of release
3. **Network Hygiene**: Limit connections to verified devices
4. **Physical Security**: Enable device lock screen
5. **App Permissions**: Grant only required permissions

### Warning Signs of Compromise
- Unexpected signature verification failures
- Frequent message chain breaks
- Unusual battery drain
- Devices appearing without being nearby
- Messages from unrecognized fingerprints

### Emergency Procedures

If you suspect compromise:
1. Immediately close the app
2. Turn off Bluetooth
3. Document suspicious behavior
4. Report to SzyYP@proton.me
5. Wait for security advisory before reconnecting

## Development Security

### Code Review Requirements
- All cryptographic changes require security review
- Protocol modifications require threat modeling
- New dependencies require vulnerability scanning

### Security Testing
- Automated fuzzing of message parsing
- Protocol conformance testing
- Cryptographic test vectors
- Penetration testing before major releases

## Compliance

GhostComm is designed for legitimate, legal communication:
- **No Backdoors**: We will never implement deliberate weaknesses
- **No Key Escrow**: Users control their keys exclusively
- **Legal Requests**: We cannot decrypt user messages
- **Transparency Reports**: Published quarterly

## Version History

| Version | Security Enhancement | Date |
| ------- | ------------------- | ---- |
| 2.1.0   | Mandatory signature verification | Jan 2025 |
| 2.0.0   | Protocol v2 with message chains | Dec 2024 |
| 1.0.0   | Initial Double Ratchet | Nov 2024 |

## Contact

**Security Issues**: SzyYP@proton.me  
**General Questions**: [GitHub Issues]  
**Updates**: [Security Advisory Page - TBD]

---

*This security policy is a living document and will be updated as the threat landscape evolves.*

*Last Updated: January 2025*  
*Next Review: April 2025*
