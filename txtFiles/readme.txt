COMO COMPILAR
Para compilar o projeto, abrir o terminal na pasta root do projeto e executar o comando: javac -d bin src/entities/*.java src/handlers/*.java src/server/*.java src/client/*.java

COMO EXECUTAR
Para executar o server, executar o comando: java -cp .\bin server.IoTServer <port> <pw_cifra> <keystore> <pw_keystore> <2FA-APIKey>
Para executar um cliente, executar o comando: java -cp .\bin client.IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>

LIMITAÇÕES DO TRABALHO

4.4 e 5. nao funcionais

//////////////////////////////////////////////////////////////////////////////////////

java -cp .\bin server.IoTServer 12345 AES serverKeys.server SegC-029 GOKYAaY1GHNIBjeeR84p 
java -cp .\bin client.IoTDevice localhost:12345 truststore.client serverKeys.server SegC-029 1 afonso.aleluia@gmail.com   
