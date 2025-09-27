# GhostComm License

Version 1.0, January 2025

Copyright (c) 2025 LCpl Szymon Procak. All rights reserved.

## Preamble

GhostComm represents a novel implementation of serverless, encrypted peer-to-peer messaging over Bluetooth mesh networks. This license governs the use, modification, and distribution of the GhostComm software while protecting the intellectual property rights of its creator.

## Definitions

- **"The Software"**: The GhostComm application, including all source code, documentation, and associated configuration files.
- **"Protocol v2.1"**: The specific cryptographic protocol implementation designed for GhostComm.
- **"Core Innovation"**: The unique combination of technologies, architecture, and design decisions that comprise GhostComm.
- **"Derivative Work"**: Any software that incorporates, modifies, or is based upon The Software.
- **"Commercial Use"**: Any use of The Software for direct or indirect commercial advantage or monetary compensation.

## Grant of License

Subject to the terms and conditions of this License, the copyright holder hereby grants you a worldwide, royalty-free, non-exclusive, perpetual license to:

### 1. Permitted Uses

- **Use** The Software for personal, educational, and non-commercial research purposes
- **Study** the source code to understand the implementation
- **Modify** The Software for personal use or contribution back to the project
- **Distribute** copies of the original Software with this license intact
- **Create** Derivative Works for non-commercial purposes

### 2. Requirements

When exercising the rights granted above, you MUST:

a) **Attribution**: Provide clear and prominent attribution to LCpl Szymon 'Si' Procak as the original creator of GhostComm in:
   - Any derivative work's documentation
   - Application "About" screens or credits
   - Repository README files
   - Academic papers or publications

b) **License Preservation**: Include this complete license in all copies or substantial portions of The Software

c) **Modification Notice**: Clearly indicate any modifications made to the original Software with:
   - Description of changes
   - Date of modifications
   - Identity of modifier

d) **Protocol Attribution**: When implementing Protocol v2.1 or similar cryptographic schemes inspired by this work, acknowledge the GhostComm project as the reference implementation

## Restrictions

### 1. Proprietary Elements

The following elements are proprietary and may NOT be used without explicit written permission:

- **Visual Assets**: All logos, icons, graphics, and visual design elements
- **Marketing Materials**: Product descriptions, promotional content, and branding
- **Architecture Design**: The specific architectural pattern combining:
  - iBeacon advertisement with Protocol v2.1 security
  - Message chain integrity with Double Ratchet encryption
  - The particular selection and combination of cryptographic primitives
- **Product Identity**: The name "GhostComm" and associated branding

### 2. Commercial Restrictions

Commercial use requires a separate commercial license. You may NOT:
- Sell The Software or Derivative Works
- Offer The Software as a service (SaaS)
- Incorporate The Software into commercial products
- Use The Software for government or military applications without permission

### 3. Patent Claims

This license does not grant any patent rights. The copyright holder reserves all patent rights to:
- The novel combination of BLE mesh networking with Protocol v2.1
- The specific message chain integrity implementation
- The ephemeral identity system with rotating addresses

## Special Provisions

### 1. Security Research

Security researchers may analyze and publish findings about The Software provided:
- Responsible disclosure practices are followed (90-day disclosure window)
- The copyright holder is notified before public disclosure
- Attribution is provided in any publications

### 2. Academic Use

Academic institutions may use The Software for research and teaching provided:
- No commercial benefit is derived
- Published research cites GhostComm and its creator
- Improvements are contributed back to the open-source project

### 3. Humanitarian Use

The copyright holder may grant special licenses for humanitarian purposes, including:
- Disaster relief operations
- Human rights organizations
- Medical emergency communications

Contact the copyright holder for humanitarian licensing.

## Intellectual Property Notice

The following innovations are claimed as intellectual property of LCpl Szymon 'Si' Procak:

1. **Protocol Design**: The specific implementation of Protocol v2.1 combining:
   - Ed25519 signatures with X25519 key exchange
   - Message chain integrity using SHA-256 hash linking
   - Sequence number verification with configurable gap tolerance
   - The particular rate limiting and anti-DoS mechanisms

2. **Architectural Innovation**: The unique system architecture including:
   - Separation of platform-specific BLE operations from protocol logic
   - Fragment reassembly state machine with timeout protection
   - Connection pooling with health monitoring
   - Message queuing during disconnection

3. **Security Model**: The comprehensive security approach incorporating:
   - Mandatory signature verification for all messages
   - Public key caching with TTL optimization
   - Chain break threshold enforcement
   - Session state management across reconnections

## Disclaimer of Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

THE SOFTWARE IS DESIGNED FOR LEGITIMATE COMMUNICATION PURPOSES. THE COPYRIGHT HOLDER EXPRESSLY DISCLAIMS RESPONSIBILITY FOR ANY MISUSE, INCLUDING BUT NOT LIMITED TO ILLEGAL SURVEILLANCE, UNAUTHORIZED INTERCEPTION OF COMMUNICATIONS, OR VIOLATION OF PRIVACY LAWS.

## Termination

This License automatically terminates if you:
1. Violate any of its terms
2. Initiate patent litigation against the copyright holder
3. Use The Software for illegal purposes

Upon termination, you must:
- Cease all use of The Software
- Destroy all copies in your possession
- Remove The Software from any systems under your control

## Governance

### 1. Interpretation
This License shall be interpreted under the laws of England and Wales, without regard to conflict of law provisions.

### 2. Severability
If any provision is found invalid, the remaining provisions shall continue in effect.

### 3. Entire Agreement
This License constitutes the entire agreement concerning The Software.

### 4. Modifications
Only the copyright holder may modify this License. Updates will be published with new version numbers.

## Contact Information

**Copyright Holder**: LCpl Szymon Procak
**Project**: GhostComm  
**Repository**: https://github.com/Szyyi/GhostCommV2  
**Contact**: SzyYP@proton.me

For commercial licensing, humanitarian exceptions, or questions about this license, contact the copyright holder.

## Acknowledgments

This software incorporates open-source libraries under their respective licenses:
- React Native (MIT License)
- React Native BLE PLX (Apache 2.0)
- Other dependencies as specified in package.json

---

By using, modifying, or distributing GhostComm, you acknowledge that you have read, understood, and agree to be bound by the terms of this License.

Last Updated: January 2025
