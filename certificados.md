## Crear una Autoridad de Certificación (CA) autofirmada

1. Genera una clave privada para la CA usando criptografía de Curvas Elípticas (ECC):

   ```
   openssl ecparam -genkey -name prime256v1 -out ca.key
   ```

2. Crea un certificado de CA autofirmado utilizando la clave privada:

   ```
   openssl req -x509 -new -key ca.key -out ca.crt
   ```

   Proporciona la información solicitada cuando se te indique.

## Generar un certificado de servidor

1. Genera una clave privada para el servidor usando ECC:

   ```
   openssl ecparam -genkey -name prime256v1 -out server.key
   ```

2. Crea una solicitud de firma de certificado (CSR) para el servidor:

   ```
   openssl req -new -key server.key -out server.csr
   ```

   Ingresa la información solicitada, incluido el Nombre Común (CN) para el servidor.

3. Firma el CSR del servidor utilizando la CA:

   ```
   openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
   ```

## Generar un certificado de cliente

1. Genera una clave privada para el cliente usando ECC:

   ```
   openssl ecparam -genkey -name prime256v1 -out client.key
   ```

2. Crea una solicitud de firma de certificado (CSR) para el cliente:

   ```
   openssl req -new -key client.key -out client.csr
   ```

   Ingresa la información requerida, incluido el Nombre Común (CN) para el cliente.

3. Firma el CSR del cliente utilizando la CA:

   ```
   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
   ```

Ahora tenemos el certificado de la CA (ca.crt), el certificado del servidor (server.crt y server.key) y el certificado del cliente (client.crt y client.key) para usar en la comunicación MQTT. Recuerda ajustar los nombres de los archivos y rutas según sea necesario en tu configuración específica.
