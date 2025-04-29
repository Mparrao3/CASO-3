
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;

public class GeneradorLlavesRSA {

    public static void main(String[] args) {
        try {
            // RSA
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair parLlaves = generator.generateKeyPair();

            PrivateKey llavePrivada = parLlaves.getPrivate();
            PublicKey llavePublica = parLlaves.getPublic();

            guardarObjeto("keys/privada.txt", llavePrivada);
            guardarObjeto("keys/publica.txt", llavePublica);

            System.out.println(" Llaves RSA generadas.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void guardarObjeto(String archivo, Object objeto) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(archivo))) {
            oos.writeObject(objeto);
        }
    }
}
