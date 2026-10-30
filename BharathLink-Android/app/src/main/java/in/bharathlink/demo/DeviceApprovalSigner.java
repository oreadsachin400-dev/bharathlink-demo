package in.bharathlink.demo;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * TEST-only signing-key primitive. Not wired to enrollment or E2EE yet.
 * AndroidKeyStore retains the private key; only the public key may be exported.
 * This is P-256 ECDSA and MUST NOT be confused with E2EE V2 Ed25519/X25519 keys.
 */
public final class DeviceApprovalSigner {
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String PREFIX = "bharathlink.test.approval.p256.";
    private DeviceApprovalSigner() {}

    private static String alias(String accountId) {
        if (accountId == null || !accountId.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Account UUID required");
        }
        return PREFIX + accountId.toLowerCase(java.util.Locale.ROOT);
    }

    public static synchronized byte[] getOrCreatePublicKey(String accountId) throws Exception {
        String keyAlias = alias(accountId);
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        if (!store.containsAlias(keyAlias)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, PROVIDER);
            generator.initialize(new KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build());
            generator.generateKeyPair();
        }
        java.security.cert.Certificate cert = store.getCertificate(keyAlias);
        if (cert == null) throw new IllegalStateException("Missing public key");
        return cert.getPublicKey().getEncoded(); // X.509 SubjectPublicKeyInfo
    }

    /** Caller must supply a server-defined, domain-separated canonical challenge. */
    public static byte[] signCanonicalChallenge(String accountId, byte[] canonicalChallenge)
            throws Exception {
        if (canonicalChallenge == null || canonicalChallenge.length == 0 ||
            canonicalChallenge.length > 4096)
            throw new IllegalArgumentException("Invalid challenge");
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        java.security.Key key = store.getKey(alias(accountId), null);
        if (!(key instanceof java.security.PrivateKey))
            throw new IllegalStateException("Approval key not enrolled");
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign((java.security.PrivateKey) key);
        signature.update(canonicalChallenge);
        return signature.sign(); // ASN.1 DER; backend must verify this exact format
    }
}
