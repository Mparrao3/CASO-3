package server;

import common.DHUtils;
import common.LlaveSesionUtils;
import common.AESUtils;
import common.HMACUtils;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;

public class ServidorPrincipal {

    // TABLA DE SERVICIOS (ID, NOMBRE, IP, PUERTO)
    private static final Map<Integer, String[]> servicios = Map.of(
        1, new String[]{"Consulta estado vuelo", "192.168.1.10", "6000"},
        2, new String[]{"Disponibilidad vuelos", "192.168.1.11", "6001"},
        3, new String[]{"Costo vuelo", "192.168.1.12", "6002"}
    );

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("Servidor esperando conexiones...");

        while (true) {
            Socket socket = serverSocket.accept();
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
                int id = entry.getKey();
                String nombre = entry.getValue()[0];
                tabla.append(id).append(": ").append(nombre).append("\n");
            }
            String tablaServicios = tabla.toString();

            // TIEMPOS DE CIFRADO Y FIRMA
            byte[] ivTabla = AESUtils.generarIV();
            long startCifradoTabla = System.nanoTime();
            byte[] tablaCifrada = AESUtils.cifrar(llaveAES, tablaServicios.getBytes(), ivTabla);
            long endCifradoTabla = System.nanoTime();
            System.out.println("Tiempo de cifrado tabla (ns): " + (endCifradoTabla - startCifradoTabla));

            // TIEMPOS DE CIFRADO Y FIRMA
            long startFirmaTabla = System.nanoTime();
            byte[] hmacTabla = HMACUtils.calcularHMAC(llaveHMAC, tablaCifrada);
            long endFirmaTabla = System.nanoTime();
            System.out.println("Tiempo de firma tabla (ns): " + (endFirmaTabla - startFirmaTabla));

            
            salida.writeObject(ivTabla);
            salida.writeObject(tablaCifrada);
            salida.writeObject(hmacTabla);

            
            boolean continuar = true;

            while (continuar) {
                try {
                    
                    byte[] ivID = (byte[]) entrada.readObject();
                    byte[] idCifrado = (byte[]) entrada.readObject();
                    byte[] hmacID = (byte[]) entrada.readObject();

                    // TIEMPO HMAC
                    long startVerificacionConsulta = System.nanoTime();
                    byte[] hmacCalculadoID = HMACUtils.calcularHMAC(llaveHMAC, idCifrado);
                    long endVerificacionConsulta = System.nanoTime();
                    System.out.println("Tiempo de verificación consulta (ns): " + (endVerificacionConsulta - startVerificacionConsulta));

                    if (!Arrays.equals(hmacID, hmacCalculadoID)) {
                        System.out.println("Error en la consulta (HMAC no coincide)");
                        socket.close();
                        return;
                    }

                    byte[] idDescifrado = AESUtils.descifrar(llaveAES, idCifrado, ivID);
                    String idTexto = new String(idDescifrado).trim();
                    int idServicio = Integer.parseInt(idTexto);

                    // SI EL CLIENTE QUIERE TERMINAR LA CONSULTA MANDA -1
                    if (idServicio == -1) {
                        continuar = false;
                        System.out.println("Cliente terminó sus consultas.");
                        break;
                    }

                    // IP Y PUERTO DEL SERVICIO
                    String[] datosServicio = servicios.get(idServicio);
                    String respuesta;
                    if (datosServicio != null) {
                        respuesta = datosServicio[1] + ":" + datosServicio[2];  
                    } else {
                        respuesta = "-1:-1";  // SERVICIO NO ENCONTRADO
                    }

                    // CIFRADO Y FIRMA DE RESPUESTA
                    byte[] ivRespuesta = AESUtils.generarIV();
                    byte[] respuestaCifrada = AESUtils.cifrar(llaveAES, respuesta.getBytes(), ivRespuesta);
                    byte[] hmacRespuesta = HMACUtils.calcularHMAC(llaveHMAC, respuestaCifrada);

                    salida.writeObject(ivRespuesta);
                    salida.writeObject(respuestaCifrada);
                    salida.writeObject(hmacRespuesta);

                } catch (EOFException e) {
                    
                    System.out.println("Cliente cerró conexión.");
                    continuar = false;
                }
            }

           
            socket.close();
        }
    }
}
