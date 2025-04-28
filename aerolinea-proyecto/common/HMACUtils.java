package common;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class HMACUtils {

    public static byte[] calcularHMAC(SecretKey llaveHMAC, byte[] datos) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(llaveHMAC);
        return mac.doFinal(datos);
    }
}
