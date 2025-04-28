package common;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class LlaveSesionUtils {

    public static SecretKey[] derivarLlaves(byte[] llaveCompartida) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(llaveCompartida);

        // SEPARAR LOS BITS
        byte[] aesKeyBytes = new byte[32];
        byte[] hmacKeyBytes = new byte[32];
        System.arraycopy(digest, 0, aesKeyBytes, 0, 32);
        System.arraycopy(digest, 32, hmacKeyBytes, 0, 32);

        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        SecretKey hmacKey = new javax.crypto.spec.SecretKeySpec(hmacKeyBytes, "HmacSHA256");

        return new SecretKey[]{aesKey, hmacKey};
    }
}
