package handlers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
//import java.util.Map;
//import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import entities.Domain;

public class ServerDomainHandler {

	private File domainsFile;
	private static ServerDomainHandler instance;
	private List<Domain> domains;
	private SecurityHandler sh;
	// private ConcurrentHashMap<String, ArrayList<T>> groupHistory = new
	// ConcurrentHashMap<String, ArrayList<T>>();

	public static ServerDomainHandler getInstance(SecurityHandler security)
			throws InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException {
		if (instance == null) {
			instance = new ServerDomainHandler(security);
		}

		return instance;
	}

	ServerDomainHandler(SecurityHandler security)
			throws InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException {
		this.domains = new ArrayList<>();
		File txtFolder = new File("txtFiles");
		this.domainsFile = new File("txtFiles//domains.txt");
		this.sh = security;
		try {
			if (!txtFolder.exists()) {
				txtFolder.mkdir();

			}
			if (!domainsFile.exists() || domainsFile.length() == 0) {

				domainsFile.createNewFile();
			} else {
				String data;
				if (!(data = sh.verifyIntegrity(domainsFile.getPath())).equals("nValid")) {

					getDomainsByTextFile(data);
				} else {
					domainsFile.delete();
					domainsFile.createNewFile();
				}

			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void getDomainsByTextFile(String data) {
		try {
			Scanner sc = new Scanner(data);
			while (sc.hasNextLine()) {
				String[] line = sc.nextLine().split(";");
				String[] users = null;
				String[] devices = null;

				if (line.length == 4) {
					if (!line[2].equals("")) {
						users = line[2].split(",");
					}
					devices = line[3].split(",");
				} else if (line.length == 3) {
					users = line[2].split(",");
				}
				Domain domain = new Domain(line[0], line[1]);
				domains.add(domain);
				if (users != null) {
					for (String user : users) {
						addUser(domain.getOwner(), domain.getName(), user);
					}
				}
				if (devices != null) {
					for (String device : devices) {
						addDevice(device, domain.getName());
					}
				}

			}
			sc.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int addDevice(String device, String domainId) {
		String[] user_device = device.split(":");
		for (Domain domain : domains) {
			if (domain.getName().equals(domainId)) {
				if (domain.contains_user(user_device[0]) || domain.isOwner(user_device[0])) {
					// System.out.println("domain.addDevice(device) ");
					if (!domain.contains_device(device)) {
						domain.addDevice(device);
						return 1;
					} else {
						return 2;
					}
				}
				return 0;
			}
		}
		return -1;
	}

	public Boolean newDomain(String dominioID, String creatorID) {
		if (!domainExists(dominioID)) {
			domains.add(new Domain(dominioID, creatorID));
			return true;
		}
		return false;
	}

	public int addUser(String userID, String domainID, String userToAdd) {
		for (Domain domain : domains) {
			if (domain.getName().equals(domainID)) {
				if (domain.getOwner().equals(userID)) {
					if ( !domain.contains_user(userToAdd)) { // evita o owner adicionar-se a
																							// ele proprio
						domain.addUser(userToAdd);

					} else {
						return 2; 
					}
					return 1;
				}
				return 0;
			}
		}
		return -1;
	}

	public synchronized void update_file() throws InvalidKeyException, NoSuchAlgorithmException {
		StringBuilder output;
		try {
			output = new StringBuilder();
			for (Domain domain : domains) {
				
				output.append(domain.getName() + ";" + domain.getOwner() + ";");
				if (domain.getUsers() != null) {
					for (String user : domain.getUsers()) {
						output.append(user + ",");
					}
					output.append(";");
				}
				for (String device : domain.getDevices()) {
					output.append(device + ",");
				}
				output.append("\n");
			}
			sh.writeHmacFile(output.toString(), this.domainsFile.getPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean domainExists(String domainID) {
		for (Domain d : this.domains) {
			if (d.getName().equals(domainID))
				return true;
		}
		return false;
	}

	// Verifica se o utilizador tem permissoes de leitura nesse dominio, ou seja, se
	// percente ao dominio
	public boolean userHasPermission(String user_name, String domain_ID) {
		Domain domain = getDomainByID(domain_ID);
		return domain.contains_user(user_name) || domain.isOwner(user_name);
	}

	public Domain getDomainByID(String domainID) {
		for (Domain domain : domains) {
			if (domain.getName().equals(domainID)) {
				return domain;
			}
		}
		return null;
	}

	public List<String> getDevicesInDomain(String domainID) {
		Domain domain = getDomainByID(domainID);
		return domain.getDevices();
	}

	public boolean userHasPermissionToRead(String user_name, String user_2) {
		for (Domain domain : domains) {
			if (userHasPermission(user_name, domain.getName())
					&& userHasPermission(user_2, domain.getName())) {
				return true;
			}
		}
		return false;
	}
}