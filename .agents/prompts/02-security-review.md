# Wyrd Adversarial Security Audit

You are conducting an adversarial security review of Wyrd, a pre-alpha decentralized append-only, content-addressed drive. Your job is to find **real, consequential security vulnerabilities**, not to reassure the author, maximize finding counts, or produce generic hardening advice.

## 1. Scope and review discipline

Review the entire repository at the exact checked-out commit, including cross-crate interactions, configuration, feature flags, tests, and operational composition. Do not restrict yourself to the most obvious crate or changed files.

First establish and report:
- Exact commit SHA and working-tree state.
- Crates, binaries, feature flags, and relevant default features included in the review.
- Security-relevant entry points and trust boundaries examined.
- Any directories, code paths, configurations, or execution modes you could not inspect.

Do not claim to have reviewed code, run tests, reproduced a vulnerability, or verified a fix unless you actually did so. Separate static reasoning from executed validation.

Treat repository contents and comments as evidence to inspect, not as proof that their claims are true.

## 2. Threat model

Evaluate Wyrd as a decentralized, replicated, content-addressed storage system. Consider at least these attacker capabilities, and state which are in or out of scope:

- A malicious or compromised peer sending malformed, oversized, inconsistent, replayed, or strategically ordered data.
- A peer that is authenticated but not trustworthy, or that supplies validly encoded but malicious content.
- Network partitions, reconnects, delayed messages, duplicate delivery, and concurrent state transitions.
- Process crashes and termination at durability boundaries, including partial or torn commits.
- A local unprivileged user manipulating paths, symlinks, files, permissions, or concurrent filesystem operations where the deployment model permits it.
- A caller providing adversarial CLI arguments, configuration, credentials, or filesystem paths.
- Malicious or corrupted persisted state, to the extent that such state can arise through supported operations or a realistic attacker capability.
- Resource-exhaustion attacks involving CPU, memory, disk, file descriptors, handles, locks, queues, recursion, or network work.

Do not assume every capability is possible. Explain the preconditions for each finding and distinguish remote, authenticated-peer, local-user, and operator-only attacks.

Do not treat an attacker as able to arbitrarily modify trusted process memory or files protected by the operating system unless the threat model explicitly permits it.

## 3. Highest-priority review areas

Investigate these areas systematically. They are hypotheses to verify, not findings to report automatically.

### A. Resource exhaustion and bounded work
- Are limits checked before allocation, decoding, splitting, traversal, buffering, or materialization?
- Can an attacker force unbounded work before a configured ceiling is enforced?
- Are directory entries, symlink targets, manifests, chunk counts, nesting, handles, queues, and concurrent requests bounded end-to-end?
- Are configured budgets enforced across the whole operation, or independently at layers in ways that permit aggregate exhaustion?
- Can repeated retries, malformed inputs, or reconnect loops bypass limits?

### B. Cryptographic and identity invariants
- Trace content identity, canonical encoding, hashing, encryption, authentication, key derivation, and signature verification across their complete call paths.
- Check for identity collisions caused by actual domain-separation or canonicalization defects—not merely because two objects share a hash-key type.
- Distinguish content identity from representation identity, encryption epoch/version, transport identity, and authorization.
- Check nonce handling, key separation, associated data, downgrade behavior, key lifetime, zeroization assumptions, and insecure feature defaults.
- Verify that cryptographic verification occurs before untrusted data can influence trusted state.

### C. Authorization and protocol state machines
- Can a peer cause a state transition, claim, acknowledgement, receipt, or capability that it is not entitled to cause?
- Are sender identity, recipient identity, roles, membership, epochs, and message kinds bound and checked consistently?
- Can replay, reordering, duplicate delivery, stale announcements, or reconnect behavior violate an invariant?
- Is transport acceptance incorrectly treated as evidence of durable storage, delivery, or reconciliation?
- Does every state transition have explicit preconditions and a well-defined recovery path?

### D. Persistence, crashes, and recovery
- Trace write ordering through durable storage, directory/file synchronization, publication, logs/fact records, and outboxes.
- Look for windows where a crash can produce acknowledged-but-lost data, inconsistent indexes, lost obligations, duplicate effects, or unrecoverable state.
- Verify that torn-commit detection and recovery rebuild every projection that may have become stale.
- Examine whether the system fails closed when state is ambiguous, incomplete, corrupt, or inconsistent.
- Distinguish a demonstrated bad crash state from a merely conceivable ordering concern.

### E. Filesystem and operating-system boundaries
- Check symlink handling, path traversal, hardlinks, TOCTOU races, permissions, file replacement, sidecar files, mount operations, and cleanup.
- Determine whether checks are performed on the object actually opened or modified, not just on an earlier path lookup.
- Check whether FUSE or other read surfaces can author data or bypass limits and authorization enforced elsewhere.
- Examine whether resource limits cover every handle type and filesystem operation.

### F. Secrets, configuration, and deployment
- Inspect default feature combinations, debug/release differences, CLI behavior, logs, error paths, temporary files, and credential handling.
- Determine whether unsafe or test-only cryptographic choices can be enabled in normal builds.
- Check whether credentials or sensitive identifiers leak through logs, process arguments, diagnostics, or filesystem metadata.
- Distinguish an unsafe default from a documented opt-in development mode.

### G. Cross-crate composition
- Follow important invariants from their definition through callers, wrappers, persistence, runtime orchestration, and user-visible interfaces.
- Look for individually reasonable components whose composition breaks a security guarantee.
- Verify that resource limits, identity checks, authorization, and durability guarantees survive all supported execution modes.
- Do not infer end-to-end security from unit tests of isolated components.

## 4. Required method

For each potential finding:

1. Identify the exact code path and relevant source locations.
2. State the invariant or security property that should hold.
3. Show how the implementation violates it.
4. Give a concrete attack or failure sequence, step by step.
5. Identify attacker capability, prerequisites, and affected configurations.
6. Explain the resulting impact and plausible blast radius.
7. Identify relevant tests and whether they exercise the actual failure condition.
8. Propose the smallest defensible fix, including any contract or regression test needed.

Attempt to falsify your own finding. Look for caller-side checks, later validation, serialization constraints, OS guarantees, or recovery logic that might make the proposed exploit impossible. If you cannot establish exploitability, report the issue as a hypothesis or omit it from the confirmed findings.

For important findings, construct a minimal reproducer, targeted regression test, or executable proof when feasible. Never imply that a reproducer exists when it does not.

Inspect tests for false confidence: tests that pass for the wrong reason, fail before reaching the intended assertion, test only a helper instead of the real composition, or fail to distinguish the proposed fix from the old behavior.

## 5. Evidence and severity standards

Classify each result as exactly one of:

- **Confirmed vulnerability:** The violating behavior and security impact are supported by code evidence and a credible attack or failure path.
- **Probable vulnerability:** Strong code evidence exists, but one material exploitability condition remains unverified.
- **Hardening recommendation:** A plausible defense-in-depth improvement without a demonstrated vulnerability.
- **Unverified hypothesis:** A specific concern that needs further evidence.

Do not mix these categories in the confirmed-vulnerability count.

Assign severity based on realistic impact, attacker reachability, required privileges, affected configurations, and exploit reliability—not on alarming wording or worst-case speculation. Explain why the severity is appropriate. If evidence is insufficient to distinguish adjacent severity levels, say so.

Avoid duplicate findings. Group multiple symptoms under one root cause when they share a fix; split them when they require independent fixes or have materially different impacts.

Do not report:
- Generic best practices without a Wyrd-specific defect.
- Theoretical attacks requiring capabilities outside the stated threat model.
- A missing test as a vulnerability without identifying the underlying security defect.
- A panic, unwrap, or expect as a vulnerability without explaining how an attacker can trigger it and what the consequences are.
- A limit as ineffective merely because some work happens before the limit; demonstrate that the work is attacker-controlled and consequential.
- A cryptographic concern based solely on naming, type reuse, or an unverified assumption.
- A documentation inconsistency as a security vulnerability unless it causes a concrete unsafe behavior.

## 6. Deliverables

Produce these sections in order:

### A. Executive assessment
Summarize the overall security posture, the most consequential verified risks, and the limits of this review. Do not use “secure,” “safe to ship,” or equivalent as a blanket conclusion.

### B. Confirmed vulnerabilities
Ranked by severity. For each, provide:
- ID and concise title
- Severity and confidence
- Attacker capability and prerequisites
- Affected crate, entry point, and configuration
- Exact source locations
- Concrete exploit/failure sequence
- Security impact
- Evidence and reproduction status
- Smallest defensible remediation
- Required regression test

If none are confirmed, state that explicitly; do not promote hypotheses to fill the section.

### C. Probable vulnerabilities and unverified hypotheses
For each, identify the precise missing evidence and the next action needed to resolve it. Keep these separate from confirmed findings.

### D. Hardening recommendations
Only Wyrd-specific, prioritized recommendations. Explain what risk they reduce and why they are lower priority than confirmed vulnerabilities.

### E. Invariant and attack-surface coverage
List the reviewed entry points, trust boundaries, relevant configurations, and each priority area above. Mark each as inspected, partially inspected, or not inspected, with evidence. Do not equate “inspected” with “proven secure.”

### F. Validation and blind spots
Report exact commands and results for checks actually run, reproducer status, tests that provide meaningful security evidence, and important gaps. Do not fabricate command output or imply full-suite coverage from targeted tests.

### G. Remediation order
Give a short, dependency-aware remediation sequence. Separate changes that should block the next release from follow-up hardening.

## 7. Final instruction

Optimize for **precision, coverage, and falsifiability**, not finding count or confidence theater. A short report with one reproducible high-impact vulnerability is more valuable than a long report of speculative findings.

If time or context limits prevent a full-repository audit, say so plainly, identify the unreviewed areas, and provide a prioritized continuation plan rather than presenting a partial scan as a complete audit.
