package server;

import common.DHUtils;
import common.LlaveSesionUtils;
import common.AESUtils;
import common.HMACUtils;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;

public class ServidorAuxiliar {

    private static final Map<Integer, String[]> servicios = Map.of(
        1, new String[]{"Consulta estado vuelo", "192.168.1.10", "6000"},
        2, new String[]{"Disponibilidad vuelos", "192.168.1.11", "6001"},
        3, new String[]{"Costo vuelo", "192.168.1.12", "6002"}
    );

    public static void main(String[] args) throws Exception {
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair parRSA = keyGen.generateKeyPair();
        PublicKey llavePublicaRSA = parRSA.getPublic();
        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("Servidor auxiliar esperando conexiones...");

        while (true) {
            try (Socket socket = serverSocket.accept()) {
                System.out.println("Cliente conectado.");

                ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream entrada = new ObjectInputStream(socket.getInputStream());

                // DIFFIE-HELLMAN
                KeyPair parServidor = DHUtils.generarLlaveDH();
                DHPublicKey publicKeyServidor = (DHPublicKey) parServidor.getPublic();

                DHParameterSpec params = publicKeyServidor.getParams();
                salida.writeObject(params.getP());
                salida.writeObject(params.getG());

                byte[] llavePublicaServidor = publicKeyServidor.getEncoded();
                salida.writeObject(llavePublicaServidor);

                // LLAVE PUBLICA
                byte[] llavePublicaClienteBytes = (byte[]) entrada.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                PublicKey llavePublicaCliente = keyFactory.generatePublic(new X509EncodedKeySpec(llavePublicaClienteBytes));

                byte[] llaveCompartida = DHUtils.calcularLlaveCompartida(parServidor.getPrivate(), llavePublicaCliente);
                SecretKey[] llavesSesion = LlaveSesionUtils.derivarLlaves(llaveCompartida);
                SecretKey llaveAES = llavesSesion[0];
                SecretKey llaveHMAC = llavesSesion[1];

                // TABLA DE SERVICIOS
                StringBuilder tabla = new StringBuilder();
                for (Map.Entry<Integer, String[]> entry : servicios.entrySet()) {
                    tabla.append(entry.getKey()).append(": ").append(entry.getValue()[0]).append("\n");
                }
                String tablaServicios = tabla.toString();

                // CIFRADO DE LA TABLA
                byte[] ivTabla = AESUtils.generarIV();
                byte[] tablaCifrada = AESUtils.cifrar(llaveAES, tablaServicios.getBytes(), ivTabla);
                byte[] hmacTabla = HMACUtils.calcularHMAC(llaveHMAC, tablaCifrada);
                salida.writeObject(ivTabla);
                salida.writeObject(tablaCifrada);
                salida.writeObject(hmacTabla);

                boolean continuar = true;
                while (continuar) {
                    try {
                        
                        byte[] ivID = (byte[]) entrada.readObject();
                        byte[] idCifrado = (byte[]) entrada.readObject();
                        byte[] hmacID = (byte[]) entrada.readObject();

                        // HMAC 
                        byte[] hmacCalculadoID = HMACUtils.calcularHMAC(llaveHMAC, idCifrado);
                        if (!Arrays.equals(hmacID, hmacCalculadoID)) {
                            System.out.println("Error en la consulta (HMAC no coincide)");
                            break;
                        }

                        // DESCIFRAR ID
                        byte[] idDescifrado = AESUtils.descifrar(llaveAES, idCifrado, ivID);
                        int idServicio = Integer.parseInt(new String(idDescifrado).trim());
                        if (idServicio == -1) break;

                        
                        String[] datos = servicios.getOrDefault(idServicio, new String[]{"-1","-1","-1"});
                        String respuesta = datos[1] + ":" + datos[2];

                        // AES
                        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        IvParameterSpec ivSpec = new IvParameterSpec(AESUtils.generarIV());
                        long startAES = System.nanoTime();
                        cipherAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
                        byte[] cifradoAES = cipherAES.doFinal(respuesta.getBytes());
                        long endAES = System.nanoTime();
                        System.out.println("Tiempo AES total (ns): " + (endAES - startAES));

                        // RSA
                        long startRSA = System.nanoTime();
                        cipherRSA.init(Cipher.ENCRYPT_MODE, llavePublicaRSA);
                        byte[] cifradoRSA = cipherRSA.doFinal(respuesta.getBytes());
                        long endRSA = System.nanoTime();
                        System.out.println("Tiempo RSA total (ns): " + (endRSA - startRSA));

                        
                        byte[] hmacRes = HMACUtils.calcularHMAC(llaveHMAC, cifradoAES);
                        salida.writeObject(ivSpec.getIV());
                        salida.writeObject(cifradoAES);
                        salida.writeObject(hmacRes);

                    } catch (EOFException eof) {
                        continuar = false;
                    }
                }
                socket.close();
            }
        }
    }
}
