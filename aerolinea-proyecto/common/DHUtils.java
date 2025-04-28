package common;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;

public class DHUtils {

    public static KeyPair generarLlaveDH() throws Exception {
        // DH
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        return keyPairGen.generateKeyPair();
    }

    public static byte[] calcularLlaveCompartida(PrivateKey propiaPrivada, PublicKey otraPublica) throws Exception {
        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
        acuerdo.init(propiaPrivada);
        acuerdo.doPhase(otraPublica, true);
        return acuerdo.generateSecret();
    }
}
