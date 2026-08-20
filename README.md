# Vault Camera

Vault Camera is a high-security, zero-trust Android camera built with Flutter. It encrypts image bytes in-memory with AES-256 and stores only encrypted `.vault` files on disk. Biometric authentication is required to access the encryption key.

Key features:
- AES-256 encryption (encrypt package)
- Hardware-backed key storage (flutter_secure_storage)
- Biometric gating (local_auth)
- Camera capture with immediate in-memory encryption (camera)
- Encrypted gallery with in-memory decryption for previews and viewing

See `lib/main.dart` for the full single-file implementation.
