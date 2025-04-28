package common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESUtils {

    public static byte[] cifrar(SecretKey llave, byte[] datos, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llave, new IvParameterSpec(iv));
        return cipher.doFinal(datos);
    }

    public static byte[] descifrar(SecretKey llave, byte[] datosCifrados, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llave, new IvParameterSpec(iv));
        return cipher.doFinal(datosCifrados);
    }

    public static byte[] generarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
