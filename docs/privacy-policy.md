# Privacy Policy

**Last Updated: January 27, 2025**  
**Effective Date: January 27, 2025**

## Introduction

This Privacy Policy governs the use of GhostComm, a military-grade serverless peer-to-peer messaging application that operates exclusively through Bluetooth Low Energy mesh networks. This document describes our commitment to absolute privacy through technical architecture rather than mere policy promises.

GhostComm represents a fundamental departure from traditional messaging applications. We have engineered a system that makes privacy violations technically impossible rather than merely prohibited by policy. This document explains how our zero-knowledge architecture, military-grade cryptography, and complete absence of infrastructure ensure that your communications remain absolutely private.

## Core Privacy Architecture

GhostComm implements a zero-knowledge architecture where privacy is guaranteed through technical impossibility rather than organizational policy. The application operates without any servers, backend infrastructure, or internet connectivity. All communication occurs directly between devices using Bluetooth Low Energy, with no intermediary systems capable of observing, storing, or analyzing your communications.

Our privacy protection is built on multiple cryptographic layers. Every message is protected by the Double Ratchet Algorithm, the same protocol used by Signal, providing Perfect Forward Secrecy and Post-Compromise Security. This means that even if encryption keys are somehow compromised, past communications remain secure and future communications automatically re-establish security. The application uses XChaCha20-Poly1305 for message encryption with extended 24-byte nonces, Ed25519 for digital signatures, and X25519 for key exchange operations.

The system generates unique encryption keys for every single message. These keys are derived through a sophisticated ratcheting mechanism that ensures no key is ever reused. After a message is decrypted, its key is immediately destroyed and cannot be recovered. This Perfect Forward Secrecy guarantee means that there is no master key that could decrypt all communications, and no possibility of retroactive surveillance even with unlimited computational resources.

## Information We Do Not Collect

GhostComm's architecture makes it impossible for us to collect any information about you or your communications. We do not collect, store, process, or have access to any personal information, device identifiers, usage patterns, or communication content. This is not a policy choice but a technical guarantee built into the system's foundation.

The application requires no registration, account creation, or identity verification. You are never asked to provide a phone number, email address, username, or any other identifying information. The application generates cryptographic identities locally on your device without any central registration or validation. These identities exist only on your device and are never transmitted to any central system because no such system exists.

We do not collect device information of any kind. The application does not access or transmit your device model, operating system version, IP address, advertising identifiers, or any other device characteristics. The application functions identically on all devices without requiring any device-specific information or optimization data.

No usage analytics or telemetry data is collected. We have no knowledge of when you use the application, how frequently you communicate, whom you communicate with, or what features you use. The application includes no analytics libraries, crash reporting systems, or usage tracking mechanisms. Every interaction with the application occurs entirely on your device with no external reporting.

## Local Data Storage and Encryption

All data associated with GhostComm exists exclusively on your device under multiple layers of encryption. Messages are stored using XChaCha20-Poly1305 authenticated encryption with unique keys derived through HKDF-SHA256. The encryption keys themselves are protected by your device's secure storage mechanisms, utilizing the iOS Keychain on Apple devices and the Android Keystore on Android devices.

The application implements a sophisticated key hierarchy for maximum security. Your identity consists of an Ed25519 signing key pair and an X25519 encryption key pair, both generating 256-bit keys. These keys can be deterministically generated from a seed phrase using PBKDF2 with 250,000 iterations, allowing you to recover your identity on a new device while maintaining complete security. The application pre-generates bundles of 100 one-time keys to enable asynchronous key exchange with Perfect Forward Secrecy even when devices are not simultaneously online.

Message storage includes comprehensive metadata protection. Stored messages contain only the encrypted payload and minimal routing information necessary for mesh network operation. No cleartext metadata about sender, recipient, timestamp, or message content is ever stored. The application implements automatic message expiry and burn-after-reading functionality, allowing messages to be automatically deleted after specified time periods or upon first reading.

When you delete data through the application, it is immediately and irrecoverably removed from your device. The application overwrites deleted data with random bytes before deallocation to prevent forensic recovery. When you uninstall GhostComm, all associated data, including all messages, keys, and configuration, is completely removed with no residual traces.

## Bluetooth Mesh Networking Privacy

GhostComm's Bluetooth Low Energy mesh network implements multiple privacy protection mechanisms. The application uses ephemeral identifiers that rotate every 15 minutes, preventing long-term tracking of your device. These identifiers are cryptographically generated and cannot be linked across rotation periods. Additionally, the application randomizes Bluetooth MAC addresses when supported by the device hardware, providing an additional layer of anti-tracking protection.

All Bluetooth advertisements are cryptographically signed using Ed25519 signatures, preventing impersonation while maintaining privacy. The advertisement packets contain only an ephemeral identifier, a truncated identity hash for routing, and mesh network information. No personally identifying information or persistent identifiers are ever broadcast. Advertisement timing is randomized by ±500 milliseconds to prevent timing correlation attacks.

The mesh network routing system implements trust-based routing without compromising privacy. Nodes build local trust scores for other nodes based on verification status, signal stability, presence duration, and message reliability. These trust scores exist only locally on each device and are never shared or synchronized. Messages are routed through the mesh network based on these trust scores, with higher-trust nodes preferred for routing while maintaining multiple redundant paths for reliability.

Message relay through the mesh network maintains complete end-to-end encryption. Intermediate nodes cannot decrypt messages they relay, seeing only the encrypted payload and necessary routing information. The Double Ratchet protocol ensures that even if an intermediate node is compromised, it cannot decrypt past or future messages. Each hop in the mesh network decrements a time-to-live counter, preventing infinite message propagation while ensuring reliable delivery across multiple hops.

## Cryptographic Security Measures

The application implements military-grade cryptographic protocols throughout its operation. The Double Ratchet Algorithm provides both Perfect Forward Secrecy and Post-Compromise Security. Perfect Forward Secrecy ensures that compromise of long-term keys does not compromise past session keys, while Post-Compromise Security ensures that the system automatically recovers security after a compromise through continuous key ratcheting.

Every message is encrypted using XChaCha20-Poly1305, an extended-nonce variant of the ChaCha20-Poly1305 authenticated encryption algorithm. This provides both confidentiality and integrity protection with a 256-bit security level. The 24-byte nonce prevents nonce reuse even with extremely high message volumes, while the Poly1305 authenticator ensures that any message tampering is immediately detected.

Digital signatures using Ed25519 provide authentication and non-repudiation for all communications. Every message and advertisement is signed with the sender's private key, allowing recipients to verify authenticity while maintaining deniability for the message contents themselves. The application uses 256-bit fingerprints derived through SHA-256 or BLAKE3 hashing for identity verification, providing strong security while remaining manageable for human verification.

The key exchange mechanism implements an asynchronous variant of the Extended Triple Diffie-Hellman (X3DH) protocol. This allows secure session establishment even when devices are not simultaneously online, using pre-generated key bundles that provide Perfect Forward Secrecy from the first message. The protocol performs multiple Diffie-Hellman operations combining long-term and ephemeral keys to ensure maximum security against both passive and active attackers.

## Permissions and Access Control

GhostComm requires only the minimum permissions necessary for its core functionality. Bluetooth permissions are required to enable peer-to-peer communication through the mesh network. These permissions are used exclusively for discovering other GhostComm users, establishing encrypted connections, and relaying messages through the mesh network. The application does not use Bluetooth for location tracking, device fingerprinting, or any purpose other than secure communication.

Storage permissions, when granted, are used solely for storing encrypted messages and cryptographic keys on your device. The application operates within its sandboxed storage area and does not access, scan, or index any other files on your device. Photos, documents, contacts, and other personal data remain completely inaccessible to GhostComm. The application does not include any functionality for backing up data to cloud services or external storage.

The application does not request or use location permissions. While Bluetooth can theoretically be used for location determination, GhostComm does not implement any location-aware features and has no capability to determine or track your geographic position. Mesh network routing operates purely on device proximity without any geographic awareness or location-based optimization.

Notification permissions, if granted, enable purely local notifications generated entirely on your device. The application does not use push notification services that route through external servers. Notifications are triggered directly by received messages and contain only the information you configure in your privacy settings. You maintain complete control over notification content and can disable them entirely without affecting core messaging functionality.

## Identity Verification and Authentication

GhostComm implements multiple verification methods to ensure secure communications without compromising privacy. In-person verification using QR codes allows two users to cryptographically verify each other's identities by scanning codes displayed on each other's devices. This establishes a verified connection with mathematical certainty of the other party's identity.

Short Authentication Strings (SAS) provide numeric verification codes for scenarios where QR code scanning is impractical. Both parties compare a six-digit number derived from their shared cryptographic session, confirming identity without exchanging any personal information. This method is particularly useful for verification over existing trusted communication channels.

Fingerprint verification allows remote identity confirmation by comparing 256-bit cryptographic fingerprints. These fingerprints are derived from public keys using secure hash functions and can be compared over any communication channel. The application displays fingerprints in multiple formats, including hexadecimal, word lists, and visual representations, accommodating different verification scenarios and user preferences.

The web of trust model allows transitive trust relationships without central authority. When you verify another user, you can optionally sign their public key, creating a cryptographic attestation of verification. Other users can see these attestations and make trust decisions based on mutual connections, creating organic trust networks without any central verification authority or identity provider.

## Anti-Surveillance and Anti-Tracking Measures

GhostComm implements comprehensive measures to prevent surveillance and tracking. The ephemeral identifier system ensures that your device cannot be tracked over time. Identifiers rotate every 15 minutes using cryptographically secure random generation, with no mathematical relationship between successive identifiers. This prevents both passive tracking by observers and active tracking by malicious nodes in the mesh network.

Timing randomization prevents traffic analysis attacks. All network operations include random delays to prevent correlation of activities. Advertisement intervals vary by ±500 milliseconds, connection attempts include random backoff periods, and message relay includes random delays. This randomization makes it impossible to correlate activities across devices or identify communication patterns through timing analysis.

The application provides plausible deniability for all communications. Messages are signed with ephemeral keys rather than long-term identity keys, allowing you to deny having sent specific messages. The absence of central servers means there are no logs to subpoena or systems to compromise. The peer-to-peer architecture ensures that no single entity has visibility into communication patterns or social graphs.

Phantom Mode allows you to become invisible to discovery while maintaining the ability to initiate communications. In this mode, your device stops advertising its presence but continues to scan for other devices. You can initiate connections to known contacts while remaining hidden from general discovery. This provides protection in high-risk environments where mere presence in the mesh network could be problematic.

## Message Security and Privacy Features

Every message benefits from multiple layers of security. End-to-end encryption ensures that only the intended recipient can decrypt message content. Perfect Forward Secrecy means that each message uses unique keys that are destroyed after use. Post-Compromise Security ensures that even if keys are compromised, future messages automatically regain security. Message authentication prevents tampering or forgery, while replay protection prevents message duplication attacks.

The application supports various privacy-enhancing message features. Burn-after-reading messages are automatically deleted after being read once, leaving no trace on the recipient's device. Timed messages automatically delete after specified periods, from minutes to days. Message retraction allows you to delete messages from both your device and the recipient's device if they haven't been read yet.

Broadcast messages to multiple recipients use a sophisticated rotating epoch system. Each epoch lasts 24 hours with hourly key rotation within epochs. Senders use unique ephemeral keys for each broadcast, preventing correlation of broadcasts from the same sender. Recipients cannot determine other recipients of broadcasts, maintaining privacy within group communications.

The application implements comprehensive protection against various attack vectors. Replay protection using sliding windows and sequence numbers prevents message replay attacks. Rate limiting at multiple layers prevents denial-of-service attacks. Message size limits and fragmentation prevent memory exhaustion attacks. Cryptographic validation at every step prevents protocol manipulation attacks.

## Open Source Transparency and Auditing

GhostComm is released as open source software under the MIT License, with the complete source code available for public inspection. This transparency allows security researchers, privacy advocates, and interested users to verify every claim made in this privacy policy through direct code examination. The open source nature ensures that privacy protections are verifiable facts rather than unverifiable promises.

The codebase undergoes continuous community review, with all changes visible in public version control. Security vulnerabilities can be reported through responsible disclosure channels, with fixes rapidly deployed to all users. The open development process ensures that no backdoors or surveillance capabilities can be secretly introduced, as any such attempts would be immediately visible in the public repository.

We encourage security audits and academic research into GhostComm's security properties. While the application implements military-grade cryptography using well-established protocols, we acknowledge that no system is perfect. We are committed to addressing any discovered vulnerabilities promptly and transparently, with public disclosure of issues and fixes after responsible remediation periods.

The application's build process is fully reproducible, allowing anyone to verify that published binaries correspond exactly to the public source code. This prevents the distribution of modified versions with weakened security or added surveillance capabilities. Users with sufficient technical knowledge can build the application themselves, ensuring complete control over the code they run.

## Legal Compliance and Government Requests

GhostComm's architecture makes it technically impossible to comply with most forms of legal demands for user data or communications. We possess no user data, maintain no servers, have no ability to decrypt communications, and cannot identify or track users. This is not a policy position but a mathematical certainty arising from our technical architecture.

In the event of receiving legal demands, we can only explain our technical inability to comply. We cannot provide user identities because we don't know them. We cannot provide message content because we cannot decrypt it. We cannot provide communication metadata because we don't have access to it. We cannot implement wiretaps because there are no central points through which communications flow.

We are committed to transparency regarding any legal demands we receive, to the maximum extent permitted by law. However, such transparency reports would necessarily show zero data disclosures, as we have no data to disclose. Any court orders requiring us to collect data going forward would require fundamental changes to the application that would be immediately visible in the open source code.

Law enforcement agencies seeking information about GhostComm users must work directly with individual users or seek physical access to devices. We cannot provide technical assistance in breaking encryption, identifying users, or accessing communications because the system is designed to make these actions mathematically impossible. This is a feature, not a limitation, ensuring that your privacy is protected by mathematics rather than corporate policy.

## Data Retention and Deletion

GhostComm implements a zero-retention policy at the system level. Since no data ever leaves your device and no servers exist to store data, there is nothing to retain. All data exists exclusively under your control on your device, and you can delete it at any time with immediate effect.

The application provides granular deletion controls. You can delete individual messages, entire conversations, or all data at once. Deletion is immediate and irreversible, with deleted data overwritten with random bytes to prevent forensic recovery. The application also supports automatic deletion policies, allowing you to configure messages to automatically delete after specified time periods.

When you uninstall GhostComm, all associated data is completely removed from your device. This includes all messages, cryptographic keys, trust scores, and configuration data. No residual files, caches, or backups remain on the device. The absence of cloud synchronization means that uninstallation results in permanent, irreversible data loss, which is an intentional privacy feature.

Emergency data destruction is available through a panic button feature that immediately wipes all GhostComm data. This feature can be triggered through the application interface or configured gestures, providing protection in situations where immediate data destruction is necessary. The wipe is comprehensive and irreversible, overwriting all data before deletion.

## International Privacy and Jurisdiction

GhostComm operates identically worldwide without any geographic restrictions or modifications. Since all processing occurs locally on your device with no server infrastructure, there are no international data transfers, no data residency issues, and no concerns about foreign surveillance laws. Your data never crosses borders because it never leaves your device.

The absence of central infrastructure means that GhostComm cannot be compelled by any government to implement backdoors, weaken encryption, or provide surveillance capabilities. Any attempt to mandate such changes would be immediately visible in the open source code and could be rejected by users who can build their own versions or fork the project.

Privacy protections are enforced by mathematics rather than law, making them equally effective regardless of jurisdiction. The cryptographic protocols used by GhostComm are based on mathematical principles that are universal and cannot be weakened by legal decree. Your communications remain private whether you are in a country with strong privacy laws or no privacy laws at all.

The peer-to-peer architecture means that each user's data is governed by their local jurisdiction, not by the jurisdiction of a service provider. There is no terms of service arbitration, no choice of law provisions, and no forum selection clauses because there is no service provider relationship. You maintain complete sovereignty over your own communications and data.

## Updates and Security Patches

Application updates are distributed through standard app store mechanisms, with the complete source code for each version available for inspection before installation. Updates cannot introduce surveillance capabilities or weaken security without these changes being immediately visible in the public source code repository.

Security updates addressing discovered vulnerabilities are released promptly with full disclosure after appropriate remediation periods. The update process cannot be used to target specific users with modified versions because all updates are distributed publicly through app stores with corresponding public source code releases.

Users are encouraged but not required to update to the latest version. Older versions continue to function and maintain their security properties, though they may lack newer security improvements or vulnerability fixes. The protocol is designed with backward compatibility in mind, allowing users with different versions to communicate securely.

The absence of server infrastructure means that protocol updates must maintain compatibility or provide migration paths. There can be no forced updates that break compatibility, as there is no central authority to enforce such changes. This ensures that users maintain control over their software and cannot be forced to accept unwanted changes.

## Contact and Support

For questions about this Privacy Policy or GhostComm's privacy practices, you can reach us through our GitHub repository at [https://github.com/Szyyi/Ghostcommv2]. We encourage public discussion of privacy concerns through GitHub Issues, ensuring transparency in our responses and allowing the community to participate in privacy discussions.

Security vulnerabilities should be reported through responsible disclosure channels outlined in our security policy. We commit to prompt response and remediation of verified security issues, with public disclosure after fixes are deployed. Security researchers who identify significant vulnerabilities will be acknowledged in our security hall of fame with their permission.

Technical support is primarily community-driven through the open source project. Since we have no access to user data or communications, we cannot provide support for lost messages or forgotten keys. This is an intentional privacy feature, not a limitation. Users must take responsibility for their own data management and backup strategies.

We do not offer commercial support or enterprise agreements that would compromise the privacy guarantees of the system. Any organization wishing to use GhostComm must accept that we cannot provide special access, compliance modifications, or surveillance capabilities, as these would violate the fundamental architecture of the system.

## Acceptance and Acknowledgment

By using GhostComm, you acknowledge that you understand and accept the privacy protections and limitations described in this policy. You understand that the privacy guarantees arise from technical architecture rather than organizational policy, and that we have no ability to recover lost data or provide access to encrypted communications.

You acknowledge that GhostComm is experimental software that has not undergone formal security audits, and that you use it at your own risk. While we implement military-grade cryptography using well-established protocols, no security system is perfect, and you should make your own assessment of whether GhostComm meets your security and privacy needs.

You understand that the absence of central infrastructure means that you are responsible for your own data management, including any backup strategies you choose to implement. You accept that data loss through device failure, accidental deletion, or application uninstallation is permanent and irreversible, and that we cannot provide any data recovery assistance.

You recognize that the strong privacy protections provided by GhostComm may make the application unsuitable for environments requiring lawful interception capabilities, enterprise data retention, or centralized management. You accept responsibility for ensuring that your use of GhostComm complies with applicable laws and regulations in your jurisdiction.

---
**Contact Details** SzyYP@proton.me | Sentinel Alias: ronin.unwrapped920@passmail.net |
**Last Modified:** January 27, 2025  
**Version:** 2.0  
**License:** This privacy policy is released under the MIT License alongside the GhostComm source code.