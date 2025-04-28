package client;

import common.DHUtils;
import common.LlaveSesionUtils;
import common.AESUtils;
import common.HMACUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Cliente {

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5000);
        System.out.println("Conectado al servidor.");

        ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream entrada = new ObjectInputStream(socket.getInputStream());

        // DIFFIE-HELLMAN
        BigInteger p = (BigInteger) entrada.readObject();
        BigInteger g = (BigInteger) entrada.readObject();
        DHParameterSpec params = new DHParameterSpec(p, g);

        byte[] llavePublicaServidorBytes = (byte[]) entrada.readObject();
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey llavePublicaServidor = keyFactory.generatePublic(new X509EncodedKeySpec(llavePublicaServidorBytes));

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(params);
        KeyPair parCliente = keyPairGen.generateKeyPair();
        byte[] llavePublicaCliente = parCliente.getPublic().getEncoded();
        salida.writeObject(llavePublicaCliente);

        byte[] llaveCompartida = DHUtils.calcularLlaveCompartida(parCliente.getPrivate(), llavePublicaServidor);

        SecretKey[] llavesSesion = LlaveSesionUtils.derivarLlaves(llaveCompartida);
        SecretKey llaveAES = llavesSesion[0];
        SecretKey llaveHMAC = llavesSesion[1];

        // TABLA DE SERVICIOS
        byte[] ivTabla = (byte[]) entrada.readObject();
        byte[] tablaCifrada = (byte[]) entrada.readObject();
        byte[] hmacTabla = (byte[]) entrada.readObject();

        byte[] hmacCalculadoTabla = HMACUtils.calcularHMAC(llaveHMAC, tablaCifrada);
        if (!Arrays.equals(hmacTabla, hmacCalculadoTabla)) {
            System.out.println("Error en la consulta de servicios (HMAC no coincide)");
            socket.close();
            return;
        }

        byte[] tablaDescifrada = AESUtils.descifrar(llaveAES, tablaCifrada, ivTabla);
        String serviciosDisponibles = new String(tablaDescifrada);

        System.out.println("Servicios disponibles:");
        System.out.println(serviciosDisponibles);

        

        // SERVICIO SELECCIONADO
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Ingrese el ID del servicio que desea consultar: ");
        String idSeleccionado = br.readLine();

        // ID CIFRADO
        byte[] ivID = AESUtils.generarIV();
        byte[] idCifrado = AESUtils.cifrar(llaveAES, idSeleccionado.getBytes(), ivID);
        byte[] hmacID = HMACUtils.calcularHMAC(llaveHMAC, idCifrado);

        salida.writeObject(ivID); 
        salida.writeObject(idCifrado);
        salida.writeObject(hmacID);

        
        byte[] ivRespuesta = (byte[]) entrada.readObject();
        byte[] respuestaCifrada = (byte[]) entrada.readObject();
        byte[] hmacRespuesta = (byte[]) entrada.readObject();

        // HMAC
        byte[] hmacCalculadoRespuesta = HMACUtils.calcularHMAC(llaveHMAC, respuestaCifrada);
        if (!Arrays.equals(hmacRespuesta, hmacCalculadoRespuesta)) {
            System.out.println("Error en la respuesta del servidor (HMAC no coincide)");
            socket.close();
            return;
        }

        // DESCIFRADO
        byte[] respuestaDescifrada = AESUtils.descifrar(llaveAES, respuestaCifrada, ivRespuesta);
        String respuestaTexto = new String(respuestaDescifrada);

        System.out.println("Respuesta del servidor:");
        System.out.println(respuestaTexto);

        
        socket.close();
    }
}
