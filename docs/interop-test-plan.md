# Comprehensive Interoperability Test Plan

## 1. Objective

To create a new test suite, `test/crypto-interop-v2.test.ts`, that rigorously validates the interoperability of the refactored cryptographic backends. This suite will replace the existing, flawed tests and serve as a gatekeeper against future regressions.

## 2. Test Strategy

The core of the strategy is "round-trip" testing. We will test every valid combination of key generation, encryption, and decryption, including the official `age` CLI as an external reference.

### Test Matrix

| Key Generation | Encryption | Decryption | Expected Result |
| :--- | :--- | :--- | :--- |
| `age` CLI | `pak-lib` | `age` CLI | Pass |
| `age` CLI | `age` CLI | `pak-lib` | Pass |
| `pak-lib` | `age` CLI | `pak-lib` | Pass |
| `pak-lib` | `pak-lib` | `age` CLI | Pass |

## 3. Test Implementation (`test/crypto-interop-v2.test.ts`)

The new test file will contain the following structure:

1.  **`before` hook:**
    *   It will use `child_process.execSync` to call the `age-plugin-se keygen` command.
    *   It will store the generated identity and recipient in a temporary file (`test/fixtures/reference-key.txt`). This ensures we are always testing against a known-good, standard key.

2.  **Test Case 1: `pak-lib` Encrypt -> `age` CLI Decrypt**
    *   **Arrange:** Load the reference recipient from the fixture.
    *   **Act:** Use `pak-lib`'s `AgeManager` to encrypt a sample text using the reference recipient.
    *   **Assert:** Use `child_process.execSync` to call `age --decrypt` with the reference identity file and the encrypted output. The decrypted result must match the original sample text.

3.  **Test Case 2: `age` CLI Encrypt -> `pak-lib` Decrypt**
    *   **Arrange:** Load the reference recipient and identity from the fixture.
    *   **Act:** Use `child_process.execSync` to call `age --encrypt` with the reference recipient to encrypt a sample text.
    *   **Assert:** Use `pak-lib`'s `AgeManager` to decrypt the resulting file using the reference identity. The decrypted result must match the original sample text.

4.  **Test Case 3: `pak-lib` `identityToRecipient`**
    *   **Arrange:** Load the reference identity and recipient from the fixture.
    *   **Act:** Call `pak-lib`'s `identityToRecipient` method with the reference identity.
    *   **Assert:** The returned recipient must exactly match the reference recipient. This test will be run for both the `native` helper and `cli` backends on macOS.

## 4. Deprecation of Old Test

The existing `test/crypto-interop.test.ts` file will be deleted to ensure that the flawed and misleading tests are no longer run.

This comprehensive test plan will provide strong guarantees that our refactored library is fully compliant and interoperable with the official `age` ecosystem.