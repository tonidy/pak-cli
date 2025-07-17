# Interoperability Remediation Plan

This document outlines the specific code changes required to implement the interoperability standardization plan.

## 1. `SecureEnclaveManager` (`src/crypto/secure-enclave-manager.ts`)

- **Modify `initializeBackend`:** The logic will be simplified. It will now always initialize the `CLISecureEnclave` as the primary backend. If on macOS, it will also initialize the `NativeSecureEnclave` as a "helper" backend.
- **Deprecate `PureJSSecureEnclave`:** All references to the `PureJSSecureEnclave` will be removed.
- **Delegate Core Operations:** The `encrypt`, `decrypt`, and `generateKeyPair` methods will be modified to always delegate directly to the `CLISecureEnclave` instance.
- **Enhance `identityToRecipient`:** This method will be updated to first try the `NativeSecureEnclave` helper (if available) for a faster result, falling back to the `CLISecureEnclave` if necessary.

## 2. `CLISecureEnclave` (`src/crypto/backend/age-cli-secure-enclave.ts`)

- **No Major Changes:** This class is already the closest to the reference implementation. It will become the primary engine for all core cryptographic operations. We will verify its command-line arguments are fully compliant with the `age` and `age-plugin-se` tools.

## 3. `NativeSecureEnclave` (`src/crypto/backend/native-secure-enclave.ts`)

- **Remove Core Crypto Logic:** The `encrypt`, `decrypt`, and `generateKeyPair` methods will be completely removed. This eliminates the flawed, non-standard cryptographic implementations.
- **Refactor `identityToRecipient`:** This method will be retained and optimized. It will be responsible for parsing a standard `age-plugin-se` identity and using the native Swift addon to derive the corresponding recipient.
- **Remove `keyMapping`:** The stateful, in-session `keyMapping` will be deleted, as it is the source of the non-portable identity issue.

## 4. `PureJSSecureEnclave` (`src/crypto/backend/pure-js-secure-enclave.ts`)

- **Delete File:** This file will be deleted from the project to formally deprecate the backend.

## 5. `format-utils.ts` (`src/crypto/format-utils.ts`)

- **No Changes Required:** The utilities in this file are still valuable for parsing and validating the `bech32`-encoded key formats used by the `age` ecosystem.

By executing this plan, we will refactor the library to be a thin, reliable client that leverages the official `age` command-line tools, guaranteeing 100% compatibility and interoperability.