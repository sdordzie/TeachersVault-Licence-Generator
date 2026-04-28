Teacher FileVault Enterprise Secure License System

Files:
1. license-generator-secure.html
   - Private console for generating signed licenses.
   - Do not host publicly.
   - Uses ECDSA P-256 digital signatures.

2. license-validator-snippet.js
   - Paste into Teacher FileVault app.
   - Replace TFV_PUBLIC_KEY_JWK with the public key from the generator.

How to use:
1. Open license-generator-secure.html.
2. Go to Keys > Generate New Keypair.
3. Copy the Public Key JWK.
4. Paste that public key into the validator snippet in your main app.
5. Generate a license from the Generate tab.
6. Paste the license into your app.
7. Optional: run the Supabase SQL under Supabase SQL Editor for online verification, revocation and device limits.

Important:
- Keep the private key backup safe.
- Public key is safe to place inside the app.
- A license cannot be edited without breaking the signature.
