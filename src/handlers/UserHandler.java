package handlers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import entities.User;

public class UserHandler {

	private ArrayList<User> registeredUsers;
	private File usersFile;
	private static UserHandler instance;
	private Map<String, String> users;
	private SecurityHandler sh;

	public UserHandler(SecurityHandler sh) throws IOException {
		this.sh = sh;
		this.registeredUsers = new ArrayList<>();
		File txtFolder = new File("txtFiles");
		this.usersFile = new File("txtFiles//users.txt");
		try {
			if (!txtFolder.exists()) {
				txtFolder.mkdir();

			}
			if (!usersFile.exists()) {

				usersFile.createNewFile();
			} else {
				getUsersByTextFile();

			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static UserHandler getInstance(SecurityHandler sh) throws IOException {
		if (instance == null) {
			instance = new UserHandler(sh);
		}
		return instance;
	}

	public String getUserCert(String user_id) {
		String userCert = null;
		for (User u : registeredUsers) {
			if (u.getName().equals(user_id)) {
				userCert = u.getCert();
			}
		}
		return userCert;
	}

	// public String loginUser(String username, String password) {

	// for (User user : this.registeredUsers) {
	// if (user.getName().equals(username)) {
	// if (user.getPassword().equals(password)) {
	// return "OK-USER";
	// } else {
	// return "WRONG-PWD";
	// }
	// }
	// }

	// this.registeredUsers.add(new User(username, password));
	// addUser(username, password);
	// return " OK-NEW-USER";

	// }

	// // adicionar um user na lista de utilizadores registados

	private synchronized void addUser(String username, String cert_path)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		StringBuilder new_content = new StringBuilder();
		try {
			// desencripta o conteudo do ficheiro de users
			String old_content;
			if ((old_content = sh.readEncrypted(this.usersFile.getPath())) != null)
				new_content.append(old_content);

			// altera o conteudo
			new_content.append(username + ":" + cert_path + "\n");

			// encripta novamente
			sh.saveEncrypted(new_content.toString(), this.usersFile.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private synchronized void getUsersByTextFile() {
		try {
			String file_content = sh.readEncrypted(this.usersFile.getPath());
			if (file_content != null) {

				Scanner sc = new Scanner(file_content);
				while (sc.hasNextLine()) {
					String[] line = sc.nextLine().split(":");
					this.registeredUsers.add(new User(line[0], line[1]));
				}
				sc.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// public boolean device_used(String user_name, int deviceId) {
	// for (String user : this.registeredUsers) {
	// if (user.getName().equals(user_name)) {
	// for (int device : user.get_devices()) {
	// if (device == deviceId) {
	// return true;
	// }
	// }
	// user.add_device(deviceId);
	// }

	// }
	// return false;

	// }

	public boolean contains_user(String user_id) {
		for (User u : registeredUsers) {
			if (u.getName().equals(user_id)) {

				return true;
			}
		}
		return false;
	}

	public void registerUser(String user_id, String cert_path) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		addUser(user_id, cert_path);
		this.registeredUsers.add(new User(user_id, cert_path));
	}

}