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
import java.util.Random;

public class ClienteConcurrente {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Uso: java client.ClienteConcurrente <numero_clientes>");
            return;
        }

        int numeroClientes = Integer.parseInt(args[0]);
        System.out.println("Lanzando " + numeroClientes + " clientes concurrentes...");

        Thread[] clientes = new Thread[numeroClientes];

        for (int i = 0; i < numeroClientes; i++) {
            clientes[i] = new Thread(new ClienteRunnable());
            clientes[i].start();
        }

        
        for (int i = 0; i < numeroClientes; i++) {
            clientes[i].join();
        }

        System.out.println("Todos los clientes terminaron.");
    }

    static class ClienteRunnable implements Runnable {

        @Override
        public void run() {
            try {
                Socket socket = new Socket("localhost", 5000);

                ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream entrada = new ObjectInputStream(socket.getInputStream());

                // DIFFIE - HELLMAN
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

                // SELECCION ALEATORIA DE SERVICIO
                Random random = new Random();
                int idSeleccionado = 1 + random.nextInt(3);

                // ID
                byte[] ivID = AESUtils.generarIV();
                byte[] idCifrado = AESUtils.cifrar(llaveAES, String.valueOf(idSeleccionado).getBytes(), ivID);
                byte[] hmacID = HMACUtils.calcularHMAC(llaveHMAC, idCifrado);

                salida.writeObject(ivID);
                salida.writeObject(idCifrado);
                salida.writeObject(hmacID);

                
                byte[] ivRespuesta = (byte[]) entrada.readObject();
                byte[] respuestaCifrada = (byte[]) entrada.readObject();
                byte[] hmacRespuesta = (byte[]) entrada.readObject();

                byte[] hmacCalculadoRespuesta = HMACUtils.calcularHMAC(llaveHMAC, respuestaCifrada);
                if (!Arrays.equals(hmacRespuesta, hmacCalculadoRespuesta)) {
                    System.out.println("Error en la respuesta del servidor (HMAC no coincide)");
                    socket.close();
                    return;
                }

                byte[] respuestaDescifrada = AESUtils.descifrar(llaveAES, respuestaCifrada, ivRespuesta);

                
                 System.out.println("Respuesta: " + new String(respuestaDescifrada));

                socket.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
