package client;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import handlers.SecurityHandler;

public class IoTDevice {
    private ObjectInputStream inStream;
    private ObjectOutputStream outStream;
    private SecurityHandler security;

    public static void main(String[] args) throws Exception {
        IoTDevice client = new IoTDevice();

        if (args.length == 6) {
            String[] server_info = args[0].split(":");
            String truststore = args[1];
            String keystore = args[2];
            String pw_keystore = args[3];
            String dev_id = args[4];
            String user_id = args[5];

            client.startClient(server_info, truststore, keystore, pw_keystore, dev_id, user_id);
        }

    }

    public void startClient(String[] server_info, String truststore, String keystore, String pw_keystore, String dev_id,
            String user_id) throws NumberFormatException, UnknownHostException, IOException, InvalidKeyException,
            SignatureException, UnrecoverableEntryException, InvalidKeySpecException {
        try {
            System.setProperty("javax.net.ssl.keyStore", keystore);
            System.setProperty("javax.net.ssl.keyStorePassword", pw_keystore);
            System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
            System.setProperty("javax.net.ssl.trustStore", truststore);
            System.setProperty("javax.net.ssl.trustStorePassword", pw_keystore);
            this.security = new SecurityHandler(keystore, pw_keystore, truststore);
            SSLSocket socket;

            // porto especifico
            if (server_info.length > 1) {
                SocketFactory sf = SSLSocketFactory.getDefault();
                socket = (SSLSocket) sf.createSocket(server_info[0], Integer.parseInt(server_info[1]));
                // porto por omissao
            } else {
                SocketFactory sf = SSLSocketFactory.getDefault();
                socket = (SSLSocket) sf.createSocket(server_info[0], 12345);
            }

            outStream = new ObjectOutputStream(socket.getOutputStream());
            inStream = new ObjectInputStream((socket.getInputStream()));

            // Autenticacao
            try {

                Scanner sc = new Scanner(System.in);
                boolean autenticar = true;
                boolean autenticado = false;
                outStream.writeObject(user_id);
                while (autenticar && !autenticado) {

                    // 4.2.1 Pedido de autenticacao
                    // Recebe nonce
                    byte[] nonce = (byte[]) inStream.readObject();
                    // Recebe flag
                    boolean registado = (boolean) inStream.readObject();

                    boolean bemSucedido;
                    if (registado) {
                        // enviar a assinatura do nonce
                        outStream.writeObject(security.signNonce(nonce));

                        bemSucedido = inStream.readBoolean();
                    } else {
                        // enviar o nonce recebido, a assinatura e o certificado
                        outStream.writeObject(nonce);
                        nonce = security.signNonce(nonce);
                        outStream.writeObject(nonce);
                        outStream.writeObject(security.sendCertificate());

                        bemSucedido = inStream.readBoolean();

                    }

                    if (bemSucedido) {

                        // recebe uma notificação por email
                        String fromServer = (String) inStream.readObject();

                        System.out.println(fromServer);

                        // server pede para inserir o codigo enviado
                        fromServer = (String) inStream.readObject();
                        System.out.println(fromServer);

                        // cliente envia o codigo para o servidor
                        outStream.writeObject(sc.nextLine());
                        autenticado = (boolean) inStream.readObject();

                        // caso não esteja autenticado tem a opção de repetir
                        if (!autenticado) {

                            // servidor pergunta se quer repetir
                            fromServer = (String) inStream.readObject();
                            System.out.println(fromServer);

                            // cliente decide se quer ou nao repetir
                            String response = sc.nextLine();
                            outStream.writeObject(response);
                            if (response.equals("n") || response.equals("N")) {
                                autenticar = false;
                            }
                        } else {

                            // Após a autenticação do utilizador
                            // Autenticação do dispositivo
                            outStream.writeObject(dev_id);
                            Object serverResponse = inStream.readObject();
                            byte[] nonceServer;
                            if (serverResponse instanceof String && serverResponse.equals("NOK-DEVID")) {
                                // O <dev-id> é inválido, terminar a ligação
                                System.out.println("Erro: <dev-id> inválido");
                                socket.close();
                                System.exit(-1);

                            } else if (serverResponse instanceof String && serverResponse.equals("OK-DEVID")) {
                                // O <dev-id> é válido, receber o nonce do servidor
                                nonceServer = (byte[]) inStream.readObject();
                                // Calcular o hash localmente
                                byte[] executableBytes = Files.readAllBytes(Paths.get("bin//client//IoTDevice.class"));
                                byte[] nonceAndExecutable = concatenate(nonceServer, executableBytes);
                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                // usar md.update ou md.digest?
                                md.update(executableBytes);
                                byte[] localHash = md.digest(nonceAndExecutable);
                                outStream.writeObject(localHash);
                                // limpar a variável
                                serverResponse = null;
                            }
                            serverResponse = inStream.readObject();
                            if (serverResponse instanceof String && serverResponse.equals("NOK-TESTED")) {
                                // O hash não corresponde, terminar a ligação
                                System.out.println("Erro: Hash não corresponde");
                                socket.close();
                                System.exit(-1);
                            } else if (serverResponse instanceof String && serverResponse.equals("OK-TESTED"))
                                interact(inStream, outStream, sc); // interação com o servidor

                        }
                    }

                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            socket.close();
        } catch (KeyStoreException | NoSuchAlgorithmException |

                CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private byte[] concatenate(byte[] nonce1, byte[] executableBytes) {
        byte[] result = new byte[nonce1.length + executableBytes.length];
        System.arraycopy(nonce1, 0, result, 0, nonce1.length);
        System.arraycopy(executableBytes, 0, result, nonce1.length, executableBytes.length);
        return result;
    }

    private static void interact(ObjectInputStream in, ObjectOutputStream out,
            Scanner sc)
            throws IOException, ClassNotFoundException {
        System.out.print(
                "Comandos disponiveis: \n\tCREATE <dm> # Criar dominio - utilizador eh Owner\r\n\n"
                        + "\tADD <user1> <dm> # Adicionar utilizador <user1> ao dominio <dm>\n\n"
                        + "\tRD <dm> # Registar o Dispositivo atual no dominio <dm>\r\n\n"
                        + "\tET <float> # Enviar valor <float> de Temperatura para o servidor.\r\n\n"
                        + "\tEI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor.\r\n\n"
                        + "\tRT <dm> # Receber as ultimas medicoes de Temperatura de cada\r\n"
                        + "dispositivo do dominio <dm>, desde que o utilizador tenha permissoes.\r\n\n"
                        + "\tRI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo\n"
                        + "<user-id>:<dev_id> do servidor, desde que o utilizador tenha permissoes.\r");
        boolean exit = false;
        while (!exit) {
            System.out.print("\nInsira um comando: ");
            String line = sc.nextLine();
            String[] tokens = line.split(" ");
            boolean image = false;
            boolean wait = true;
            if (tokens[0].equals("CREATE")) {
                if (tokens.length != 2)
                    System.out.println("O comando CREATE eh usado na forma \"CREATE <dm>\"");
                else {
                    String domain = tokens[1];
                    try {
                        out.writeObject("CREATE");
                        out.writeObject(domain);
                        System.out.println((String) in.readObject());
                    } catch (IOException | ClassNotFoundException e) {
                        System.out.println("Erro na comunicação");
                    }
                }
            } else if (tokens[0].equals("ADD")) {
                if (tokens.length != 3)

                    System.out.println("O comando ADD eh usado na forma \"ADD <user1> <dm>\"");
                else {

                    String user_1 = tokens[1];
                    String dm = tokens[2];
                    try {
                        out.writeObject("ADD");
                        out.writeObject(user_1);
                        out.writeObject(dm);
                        System.out.println((String) in.readObject());
                    } catch (IOException | ClassNotFoundException e) {
                        System.out.println("Erro na comunicação");
                    }
                }
            } else if (tokens[0].equals("RD")) {
                if (tokens.length != 2)
                    System.out.println("O comando RD eh usado na forma \"RD <dm>\"");
                else {
                    String dm = tokens[1];
                    try {
                        out.writeObject("RD");
                        out.writeObject(dm);
                        System.out.println((String) in.readObject());
                    } catch (IOException | ClassNotFoundException e) {
                        System.out.println("Erro na comunicação");
                    }
                }
            } else if (tokens[0].equals("ET")) {
                if (tokens.length != 2)
                    System.out.println("O comando ET eh usado na forma \"ET <float>\"");
                else {
                    String tempString = tokens[1];
                    try {
                        out.writeObject("ET");
                        out.writeObject(tempString);
                        System.out.println((String) in.readObject());
                    } catch (IOException | ClassNotFoundException e) {
                        System.out.println("Erro na comunicação");
                    }
                }
            } else if (tokens[0].equals("EI")) {
                if (tokens.length != 2)
                    System.out.println("O comando EI eh usado na forma \"EI <filename.jpg>\"");
                else {
                    String img_name = tokens[1];
                    try {
                        File imgFiles = new File("imgFiles");
                        if (!imgFiles.exists())
                            imgFiles.mkdir();

                        File img = new File("imgFiles//" + img_name);

                        out.writeObject("EI");
                        long img_size = img.length();
                        out.writeObject(img_size);

                        FileInputStream file = new FileInputStream(img);
                        out.writeObject(img_name);

                        byte[] bytes = new byte[(int) img_size];
                        file.read(bytes);
                        file.close();
                        out.write(bytes);
                        out.flush();

                        out.writeObject("END");

                        String fromServer = (String) in.readObject();
                        System.out.println(fromServer);
                    } catch (IOException e) {
                        System.err.println("Erro ao ler o ficheiro :" + e.getMessage());
                    }
                }
            } else if (tokens[0].equals("RT")) {
                if (tokens.length != 2)
                    System.out.println("O comando RT eh usado na forma \"RT <dm>\"");
                else {
                    String dm = tokens[1];
                    out.writeObject("RT");
                    out.writeObject(dm);

                    String fromServer = (String) in.readObject();
                    if (fromServer.equals("OK")) {
                        System.out.print(fromServer + ", ");

                        long file_size = (Long) in.readObject();
                        System.out.print(file_size + ", ");

                        int bytesRead;
                        long totalBytesRead = 0;

                        byte[] bytes = new byte[8192];
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        while ((bytesRead = in.read(bytes)) != -1) {
                            baos.write(bytes, 0, bytesRead);
                            totalBytesRead += bytesRead;

                            // Check for the "END" signal
                            if (totalBytesRead >= file_size) {
                                // If "END" signal received, break the loop
                                if ("END".equals((String) in.readObject())) {
                                    break;
                                }
                            }
                        }
                        String receivedData = baos.toString();
                        System.out.print(receivedData);

                    } else {
                        System.out.println(fromServer);
                    }

                }
            } else if (tokens[0].equals("RI")) {
                if (tokens.length != 2)
                    System.out.println("O comando RI eh usado na forma \"RI <user_id>:<device_id>\"");
                else {
                    String device = tokens[1];
                    out.writeObject("RI");
                    out.writeObject(device);

                    String fromServer = (String) in.readObject();
                    if (fromServer.equals("OK")) {
                        System.out.print(fromServer + ", ");

                        long file_size = (Long) in.readObject();
                        System.out.print(file_size + ", ");

                        int bytesRead;
                        long totalBytesRead = 0;

                        byte[] bytes = new byte[8192];
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        while ((bytesRead = in.read(bytes)) != -1) {
                            baos.write(bytes, 0, bytesRead);
                            totalBytesRead += bytesRead;

                            // Check for the "END" signal
                            if (totalBytesRead >= file_size) {
                                // If "END" signal received, break the loop
                                if ("END".equals((String) in.readObject())) {
                                    break;
                                }
                            }
                        }
                        String receivedData = baos.toString();
                        System.out.print(receivedData);

                    } else {
                        System.out.println(fromServer);
                    }

                }
            } else if (tokens[0].equals("exit")) {
                try {
                    out.writeObject("exit");
                    exit = true;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("Comando não reconhecido.\n");
                System.out.println(
                        "Comandos disponiveis: \n\tCREATE <dm> # Criar domínio - utilizador é Owner\r\n"
                                + "\tADD <user1> <dm> # Adicionar utilizador <user1> ao domínio <dm>\n"
                                + "\tRD <dm> # Registar o Dispositivo atual no domínio <dm>\r\n"
                                + "\tET <float> # Enviar valor <float> de Temperatura para o servidor.\r\n"
                                + "\tEI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor.\r\n"
                                + "\tRT <dm> # Receber as últimas medições de Temperatura de cada\r\n"
                                + "dispositivo do domínio <dm>, desde que o utilizador tenha permissões.\r\n"
                                + "\tRI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo\n"
                                + "<user-id>:<dev_id> do servidor, desde que o utilizador tenha permissões.\r");
            }
        }
    }
}