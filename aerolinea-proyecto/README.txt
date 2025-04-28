# Desde CASO 3\aerolinea-proyecto

# Limpiar Proyecto
find . -name "*.class" -delete

# Compilar Proyecto
javac common/*.java server/*.java client/*.java

# Ejecutar

1. Lanzar servidor -------> java server.ServidorPrincipal (Terminal 1)
2. Lanzar cliente  -------> java client.Cliente (Terminal 2)


# Escenario 1

1. Lanzar servidor --------> java server.ServidorPrincipal (Terminal 1)
2. Lanzar cliente  --------> java client.ClienteIterativo (Terminal 2)

# Escenario 2

1. Lanzar servidor --------> java server.ServidorPrincipal (Terminal 1)
2. Lanzar cliente  --------> java client.ClienteConcurrente 4/16/32/64 (Terminal 2)
