# cripto_reto_LiCore

## Introduccion

En este proyecto, nos enfocaremos en la implementación de esquemas criptográficos para proteger las comunicaciones y el almacenamiento de datos en entornos de Internet de las Cosas utilizados para monitorear la producción y el consumo de energía. El escenario planteado involucra a un grupo de auditores que tienen la capacidad de recopilar datos de dispositivos inteligentes, como medidores e inversores, ubicados en diversos entornos, como residencias, comercios, instituciones educativas e instalaciones industriales equipadas con sistemas fotovoltaicos. Estos datos son enviados a un centro de control encargado de analizar la información recopilada. Nuestro objetivo es proponer un esquema de intercambio de datos que garantice la seguridad de la información al salvaguardar la confidencialidad, integridad, autenticidad y privacidad de los datos. Dado que los patrones de consumo y producción son considerados datos sensibles y no deben ser expuestos, resulta fundamental implementar un esquema que utilice una arquitectura de red viable y un protocolo criptográfico seguro para garantizar que los datos no sean comprometidos en ningún momento, desde su generación hasta su almacenamiento.

Los dispositivos del smart grid encargados de monitorear los parámetros de energía obtenidos de los medidores e inversores cuentan con una interfaz WiFi para comunicarse con el exterior en la práctica, y para fines de la simulación y el entorno de pruebas correspondientes al reto, los datos comunicados son proporcionados por la OSF en un archivo .csv lo que implica que los medidores e inversores no estarán considerados como componentes de la implementación para motivos prácticos. En este escenario, los auditores digitales que recolectarán datos de los dispositivos smart conectados a ellos serán micro-controladores con capacidad WiFi. El centro de control será una entidad virtualizada que será capaz de consultar los datos recolectados y enviados por cada uno de los auditores.

## Technologies

- Python 3.9.16
- import paho.mqtt.client as mqtt
- random
- json
- time
- ssl
- json
- datetime, timedelta
- pandas as pd
- cryptography.hazmat.primitives.ciphers: Cipher, algorithms, modes
- cryptography.hazmat.backends: default_backend
- cryptography.hazmat.primitives: padding
- os
- hashlib
- hmac.HMAC
- hashlib.sha256
- mysql.connector
- pandas as pd


## Configuración

La primera etapa consiste en el arranque, donde encendemos y configuramos los auditores y el centro de control. Para fines prácticos, utilizaremos dos máquinas virtuales con Ubuntu.

Antes de proceder, es importante establecer correctamente cada elemento de la red. Definiremos los archivos que debe tener cada componente:

1. Servidor MQTT: Utilizaremos la mosquitto en una máquina virtual con Ubuntu. Los archivos necesarios son los siguientes:
   - ca.crt
   - server.crt
   - server.key
   - client.crt
   - client.key
   - CC_ECDH_publicKey.py
   - CC_ECDH_sharedSecret.py

2. Auditor 1: Los archivos requeridos para el primer auditor son:
   - client1.crt
   - client1.key
   - subscriber_cert.py
   - publisher_cert.py
   - AU_ECDH_publicKey.py
   - AU_ECDH_sharedSecret.py

3. Auditor 2: Los archivos requeridos para el segundo auditor son:
   - client2.crt
   - client2.key
   - subscriber_cert.py
   - publisher_cert.py
   - AU_ECDH_publicKey.py
   - AU_ECDH_sharedSecret.py

## Cómo funciona

Para enviar y recibir datos, necesitamos llevar a cabo la creación e intercambio de claves públicas, que es una de las primeras etapas de nuestro desafío. Para esto, debemos compartir nuestras claves públicas y privadas utilizando el archivo CC_ECDH_publicKey.py en el centro de control, y AU_ECDH_publicKey.py en el auditor. Ambos elementos intercambiarán sus claves publicándolas en el tópico /publicKeys. Después de intercambiar las claves públicas, utilizaremos CC_ECDH_sharedSecret.py y AU_ECDH_sharedSecret.py para determinar el secreto que ambos elementos compartirán. Este proceso debe realizarse en cada sesión, que durará 8 horas.

Para utilizar este código de encriptación y desencriptación entre dos clientes, generalmente se siguen los siguientes pasos:

Cliente 1 (Emisor):
1. Generar una clave privada (privKeyA) y calcular la correspondiente clave pública (xPublicKeyA, yPublicKeyA) utilizando EccMultiply.
2. Mantener la clave privada segura y proporcionar la clave pública al receptor.

Cliente 2 (Receptor):
1. Generar una clave privada (privKeyB) y calcular la correspondiente clave pública (xPublicKeyB, yPublicKeyB) utilizando EccMultiply.
2. Mantener la clave privada segura y proporcionar la clave pública al emisor.

Cliente 1 (Emisor):
1. Multiplicar la clave pública del Cliente 2 (xPublicKeyB, yPublicKeyB) con la clave privada del Cliente 1 (privKeyA) utilizando EccMultiply para calcular el secreto compartido.
2. Utilizar el secreto compartido como clave para algoritmos de encriptación simétrica (por ejemplo, AES) para encriptar la información deseada.

Cliente 2 (Receptor):
1. Multiplicar la clave pública del Cliente 1 (xPublicKeyA, yPublicKeyA) con la clave privada del Cliente 2 (privKeyB) utilizando EccMultiply para calcular el secreto compartido.
2. Utilizar el secreto compartido como clave para algoritmos de encriptación simétrica (por ejemplo, AES) para desencriptar la información encriptada recibida.

En el archivo ECDH_vectores_de_prueba.ipynb se muestra un ejemplo de cómo utilizar estos códigos con vectores de prueba y luego encriptarlos usando la clave compartida con AES-256.


Para la parte de las curvas elípticas, debemos establecer qué curva se utilizará, en este caso será p-256. Además, debemos generar 2 claves privadas aleatorias para cada cliente y luego multiplicarlas por la curva para obtener la clave pública. Estas claves públicas deben ser enviadas a través del broker, publicándolas en el tópico /llaves. Esto se logra ejecutando los códigos ecdsa_sign.py y ecdsa_verify.py, siguiendo el siguiente proceso:

Firmante (Cliente 1) genera una clave privada (privKey).
Firmante calcula su clave pública multiplicando el punto generador (GPoint) por la clave privada.
Firmante firma un mensaje utilizando ECDSA_sign, que requiere el mensaje y la clave privada. Esto devuelve la firma (r, s).
Verificador (Cliente 2) recibe el mensaje, la firma (r, s) y la clave pública (xPublicKey, yPublicKey).
Verificador verifica la firma utilizando ECDSA_verify, que requiere el mensaje, la firma y la clave pública. El resultado de la verificación indica si la firma es válida o no.

Este proceso está incluido en publisher_cert.py y subscriber.py para automatizar el intercambio de las trazas. Sin embargo, si se desea explorar en detalle, también se incluyen los archivos ecdsa_sign.py y ecdsa_verify.py, que corresponden al auditor y al centro de control, respectivamente. Además, se incluye ecdsa_sig_verify.ipynb en caso de que se desee verificar la curva con los parámetros y asegurarse de que cumple con los requisitos del RFC6979.

Una vez que se han cumplido estos pasos, deberíamos tener los elementos de nuestra traza: encrypted_traces, iv, r, s. Estos elementos se ordenan y procesan en el código publisher_cert.py, y en subscriber_cert.py se deshace todo este proceso.

Todo lo mencionado anteriormente se considera y se puede revisar en los códigos publisher_cert.py y subscriber_cert.py, donde se incluyen los procesos que hemos mencionado. Sin embargo, a excepción del intercambio de claves y secretos, y la inserción de los datos en la base de datos, los cuales también hemos detallado anteriormente. A continuación, proporcionaremos una guía de cómo se deben utilizar los códigos en orden (el prefijo indica a qué componente nos referimos):

1. CC_ECDH_publicKey.py
2. AU_ECDH_publicKey.py
3. CC_ECDH_sharedSecret.py
4. AU_ECDH_sharedSecret.py
5. publisher_cert.py
6. subscriber_cert.py
7. sql_database.py

Los archivos donde se puede verificar cómo probamos nuestros algoritmos se encuentran en la carpeta "vectores de prueba". Allí se encuentran:
- ecdsa_sign_verify.ipynb
- ECDH_vectores_de_prueba.ipynb
- sql_database.ipynb
- publisher_cert.ipynb
- subscriber.ipynb

Y todos los códigos que utilizamos también se encuentran en su versión de Jupyter Notebook en la misma carpeta, por si se desea ver cómo probamos cada código antes de implementarlo en nuestra solución.

Además para la parte de certificados incluimos un tutorial de como crearlos que está en certificados.md, y los certificados que generamos como ejemplo siguiendo este tutorial se encuentran en la carpeta certs.

## Créditos

- Karla Olvera https://github.com/karlasov
- José Miguel Pérez https://github.com/Brito67
- Eugenio Santisteban 
- Alfredo García https://github.com/AlfredoGrcaa

