import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class GeneradorLlavesRSA {

    public static void main(String[] args) {
        try {
            // LLAVES RSA
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(1024);
            KeyPair parLlaves = generador.generateKeyPair();

            PrivateKey llavePrivada = parLlaves.getPrivate();
            PublicKey llavePublica = parLlaves.getPublic();

            
            guardarLlave("keys/private.key", llavePrivada.getEncoded());
            guardarLlave("keys/public.key", llavePublica.getEncoded());

            System.out.println("Llaves generadas exitosamente.");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    private static void guardarLlave(String archivo, byte[] llave) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(archivo)) {
            fos.write(llave);
        }
    }
}
