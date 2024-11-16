package server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OptionalDataException;
import java.io.PrintWriter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;

import java.util.Scanner;
import java.util.Random;

import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.HttpURLConnection;
import java.io.IOException;

import java.io.BufferedReader;
import java.io.File;
import java.util.Arrays;
import java.util.List;

import handlers.ServerDomainHandler;
import handlers.UserHandler;
import handlers.DevicesHandler;
import handlers.SecurityHandler;

public class IoTServer {
	private UserHandler users;
	private ServerDomainHandler domains;
	private DevicesHandler devices;
	private SecurityHandler security;

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, IOException, InvalidKeyException {
		System.out.println("IoTServer conectado!");
		IoTServer server = new IoTServer();
		// Inicia o servidor no porto especificado
		if (args.length == 5) {
			int port = Integer.parseInt(args[0]);
			String pw_cifra = args[1];
			String keystore = args[2];
			String pw_keystore = args[3];
			String APIKey = args[4];

			server.startServer(port, pw_cifra, keystore, pw_keystore, APIKey);
			// Inicia o servidor no porto 12345, por omissao
		} else if (args.length == 4) {
			String pw_cifra = args[0];
			String keystore = args[1];
			String pw_keystore = args[2];
			String APIKey = args[3];

			server.startServer(12345, pw_cifra, keystore, pw_keystore, APIKey);
		}
	}

	public void startServer(int port, String pw_cifra, String keystore, String pw_keystore, String APIKey)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException,
			IOException, InvalidKeyException {
		SSLServerSocket ss = null;

		try {
			security = new SecurityHandler(keystore, pw_keystore, null, pw_cifra);

			users = UserHandler.getInstance(security);
			devices = DevicesHandler.getInstance(security);
			domains = ServerDomainHandler.getInstance(security);

			System.setProperty("javax.net.ssl.keyStore", keystore);
			System.setProperty("javax.net.ssl.keyStorePassword", pw_keystore);
			System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");

			SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			ss = (SSLServerSocket) ssf.createServerSocket(port);

			// servidor recebe clientes
			while (true) {
				try {
					new ServerThread(ss.accept(), APIKey).start(); // uma thread por ligacao
				} catch (IOException e) {
					break;
				}
			}

			// fecha a socket do servidor
			try {
				ss.close();
			} catch (IOException e) {
				System.err.println("Erro ao fechar socket");
				e.printStackTrace();
			}
		} catch (Exception e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
		} finally {
			domains.update_file();
			devices.update_file();
		}
	}

	public class ServerThread extends Thread {

		private Socket socket;
		private String apikey;
		ObjectInputStream inStream;
		ObjectOutputStream outStream;

		ServerThread(Socket inSoc, String aPIKey) {
			socket = inSoc;
			apikey = aPIKey;
		}

		public void run() {
			try {
				inStream = new ObjectInputStream(socket.getInputStream());
				outStream = new ObjectOutputStream(socket.getOutputStream());

				// Autenticacao de um utilizador
				String user_name = null;
				int deviceId = 0;

				user_name = (String) inStream.readObject();
				boolean autenticar = true;
				boolean autenticado = false;
				while (autenticar && !autenticado) {

					if (autenticado = autenticacao1(user_name)) {
						autenticado = autenticado && autenticacao2(user_name);

						outStream.writeObject(autenticado);
						if (!autenticado) {
							outStream.writeObject("Quer tentar novamente? [y/n]: ");
							String fromServer = (String) inStream.readObject();
							if ((fromServer.equals("n") || fromServer.equals("N")) && 
							(!fromServer.equals("y") || !fromServer.equals("Y"))) {
								autenticar = false;
							}
						}
					} else
						autenticar = false;
				}

				if (autenticado) {
					// Receber o dev_id
					deviceId = Integer.parseInt((String) inStream.readObject());
					// Verificar se o dispositivo existe e está sendo usado
					boolean deviceExists = devices.exist(user_name, deviceId);
					boolean deviceUsed = devices.device_used(deviceId, user_name);
					// Atualizar o status do dispositivo se necessário
					if (!deviceExists || !deviceUsed) {
						if (!deviceExists) {
							devices.create_device(user_name, deviceId);
						}
						devices.update_device_to_used(deviceId, user_name);
						outStream.writeObject("OK-DEVID");

						// O servidor gera um nonce aleatório de 8 bytes e envia-o para o cliente
						SecureRandom secureRandom = new SecureRandom();
						byte[] nonceToClient = new byte[8];
						secureRandom.nextBytes(nonceToClient);
						outStream.writeObject(nonceToClient);

						// Receber o hash da concatenação do cliente
						byte[] clientHash = (byte[]) inStream.readObject();

						// Calcular o hash localmente
						byte[] executableBytes = Files.readAllBytes(Paths.get("bin//client//IoTDevice.class"));
						byte[] nonceAndExecutable = concatenate(nonceToClient, executableBytes);
						MessageDigest md = MessageDigest.getInstance("SHA-256");
						md.update(executableBytes);
						byte[] localHash = md.digest(nonceAndExecutable);

						// Comparar os hashes
						if (Arrays.equals(clientHash, localHash)) {
							outStream.writeObject("OK-TESTED");
							interact(user_name, deviceId, inStream, outStream, users, domains, devices);
						} else
							outStream.writeObject("NOK-TESTED");

					} else
						outStream.writeObject("NOK-DEVID");

				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		private byte[] concatenate(byte[] nonceToClient, byte[] executableBytes) {
			byte[] result = new byte[nonceToClient.length + executableBytes.length];
			System.arraycopy(nonceToClient, 0, result, 0, nonceToClient.length);
			System.arraycopy(executableBytes, 0, result, nonceToClient.length, executableBytes.length);
			return result;
		}

		private boolean autenticacao1(String user_id) throws ClassNotFoundException, IOException, InvalidKeyException,
				NoSuchAlgorithmException, CertificateException, SignatureException, NoSuchPaddingException,
				IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

			// Gera e envia nonce
			byte[] nonce = security.generateNonce(user_id);
			outStream.writeObject(nonce);
			// Verificar e enviar uma flag se o user eh conhecido
			boolean registado = users.contains_user(user_id);
			outStream.writeObject(registado);

			boolean bemSucedido = false;
			if (registado) {
				// Receber nonce assinado
				byte[] signedNonce = (byte[]) inStream.readObject();

				bemSucedido = security.confirmIdentity(users.getUserCert(user_id), nonce, signedNonce);
			} else {
				// Receber nonce, nonce assindado e o certificado
				byte[] clientNonce = (byte[]) inStream.readObject();
				byte[] signedNonce = (byte[]) inStream.readObject();
				Certificate clientCert = (Certificate) inStream.readObject();

				if (Arrays.equals(nonce, clientNonce) && security.confirmNewIdentity(clientCert, nonce, signedNonce)) {
					bemSucedido = true;
					File serverFilesDir = new File("filesServer");
					if (!serverFilesDir.exists()) {
						serverFilesDir.mkdir();

					}
					File file = new File("filesServer//" + user_id + ".cert");
					try (FileOutputStream fos = new FileOutputStream("filesServer/" + user_id + ".cert")) {
						byte[] certBytes = clientCert.getEncoded();
						fos.write(certBytes);
					} catch (CertificateException | IOException e) {
						e.printStackTrace();
					}
					users.registerUser(user_id, "filesServer/" + user_id + ".cert");
				}
			}

			outStream.writeBoolean(bemSucedido);
			return bemSucedido;
		}

		private boolean autenticacao2(String user_name)
				throws IOException, URISyntaxException, NumberFormatException, ClassNotFoundException {
			outStream.writeObject("Foi enviado um email para: " + user_name);

			// Gera codigo C2FA
			Random random = new Random();
			int randomNumber = random.nextInt(100000);
			String cod_C2FA = String.format("%05d", 5);
			URI uri = new URI("https://lmpinto.eu.pythonanywhere.com/2FA?e=" + user_name + "&c="
					+ cod_C2FA + "&a=" + apikey);
			URL url = uri.toURL();
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("GET");
			con.getResponseCode();
			con.disconnect();

			outStream.writeObject("Introduza o código enviado por email: ");
			long responce_code;
			try{
				responce_code = Long.parseLong((String) inStream.readObject());
			}catch(NumberFormatException e){
				return false;
			}

			return responce_code == Integer.parseInt(cod_C2FA);

		}

		private void interact(String user_name, int deviceId, ObjectInputStream inStream, ObjectOutputStream outStream,
				UserHandler users, ServerDomainHandler domains, DevicesHandler devices)
				throws ClassNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException {
			boolean exit = false;
			while (!exit) {
				String command = null;
				try {
					command = (String) inStream.readObject();
				} catch (OptionalDataException e) {
					command = (String) inStream.readObject();
					;
				}
				String arg1 = null;
				String arg2 = null;
				float temp;
				try {
					switch (command) {
						case "CREATE":
							arg1 = (String) inStream.readObject();
							if (domains.newDomain(arg1, user_name)) {
								outStream.writeObject("OK");
								domains.update_file();
								devices.update_file();
							} else {
								outStream.writeObject("NOK");
							}
							break;
						case "ADD":
							arg1 = (String) inStream.readObject();
							arg2 = (String) inStream.readObject();
							if (!users.contains_user(arg1)) {
								outStream.writeObject("NOUSER");
							} else {
								int result = domains.addUser(user_name, arg2, arg1);
								if (result == 1) {
									domains.update_file();
									outStream.writeObject("OK");
								} else if (result == 0) {
									outStream.writeObject("NOPERM");
								} else if (result == 2) {
									outStream.writeObject("NOK");
								} else {
									outStream.writeObject("NODM");
								}
							}
							break;
						case "RD":
							arg1 = (String) inStream.readObject();
							int result = domains.addDevice(user_name + ":" + deviceId, arg1);

							if (result == 1) {
								outStream.writeObject("OK");
								domains.update_file();
							} else if (result == 0) {
								outStream.writeObject("NOPERM");
							} else if (result == 2) {
								outStream.writeObject("NOK");
							} else {
								outStream.writeObject("NODM");
							}
							break;
						case "ET":
							arg1 = (String) inStream.readObject();
							try {
								temp = Float.parseFloat(arg1);
								devices.update_temp(deviceId, temp, user_name);
								outStream.writeObject("OK");
							} catch (NumberFormatException e) {
								outStream.writeObject("NOK");
							}
							break;
						case "EI":

							try {
								long file_size = (long) inStream.readObject();
								int bytesRead;
								long totalBytesRead = 0;

								File imgFiles = new File("imgFilesServer");
								if (!imgFiles.exists())
									imgFiles.mkdir();
								String file_name = (String) inStream.readObject();
								File image = new File("imgFilesServer//" + file_name); // ler nome
																						// da

								FileOutputStream file = new FileOutputStream(image);
								byte[] bytes = new byte[8192];
								ByteArrayOutputStream baos = new ByteArrayOutputStream();
								while ((bytesRead = inStream.read(bytes)) != -1) {
									baos.write(bytes, 0, bytesRead);
									totalBytesRead += bytesRead;

									// Check for the "END" signal
									if (totalBytesRead >= file_size) {
										// If "END" signal received, break the loop
										if ("END".equals((String) inStream.readObject())) {
											break;
										}
									}
								}

								// write the image data to a new image file
								byte[] image_data = baos.toByteArray();
								file.write(image_data);
								file.close();
								outStream.writeObject("OK");
								devices.update_device_file(deviceId, image, user_name);
							} catch (Exception e) {
								outStream.writeObject("NOK");
							}
							break;

						case "RT":
							String domain = (String) inStream.readObject();
							if (domains.domainExists(domain)) {
								if (domains.userHasPermission(user_name, domain)) {
									List<String> devicesInDomain = domains.getDevicesInDomain(domain);
									try {

										File file = devices.getTemp(devicesInDomain);
										FileInputStream fos = new FileInputStream(file);

										outStream.writeObject("OK");

										long file_size = file.length();
										outStream.writeObject("" + file_size);
										byte[] bytes = new byte[(int) file_size];
										fos.read(bytes);
										fos.close();
										outStream.write(bytes);
										outStream.flush();

										outStream.writeObject("END");

									} catch (IOException e) {
										outStream.writeObject("NODATA");
									}
								} else {
									outStream.writeObject("NOPERM");
								}
								break;
							} else {
								outStream.writeObject("NODM");

							}

							break;
						case "RI":
							String[] device = ((String) inStream.readObject()).split(":");
							if (devices.exist(device[0], Integer.parseInt(device[1]))) {
								if (domains.userHasPermissionToRead(user_name, device[0])) {
									try {

										File file = devices.getFile(device[0], Integer.parseInt(device[1]));
										long file_size = file.length();

										FileInputStream fos = new FileInputStream(file);
										outStream.writeObject("OK");

										outStream.writeObject(file_size);
										byte[] bytes = new byte[(int) file_size];
										fos.read(bytes);
										fos.close();
										outStream.write(bytes);
										outStream.flush();

										outStream.writeObject("END");

									} catch (IOException e) {
										outStream.writeObject("NODATA");
									}
								} else {
									outStream.writeObject("NOPERM");
								}
								break;
							} else {
								outStream.writeObject("NOID");

							}

							break;
						default:
							domains.update_file();
							devices.update_file();
							System.out.println("Device " + user_name + ":" + deviceId + " desconectado!");
							devices.update_device_to_not_used(deviceId, user_name);
							exit = true;
							break;
					}
				} catch (IOException e) {
					domains.update_file();
					devices.update_file();
					System.out.println("Device " + user_name + ":" + deviceId + " desconectado!");
					devices.update_device_to_not_used(deviceId, user_name);
					outStream.writeObject(e.getMessage());
				}
			}
		}

	}
}
