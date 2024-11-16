package handlers;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecurityHandler {

    private PrivateKeyEntry privateKey;
    private KeyStore ks;
    private SecretKey key;
    private String trustStorePath;
    private static final byte[] SALT = {

            (byte) 0x1a, (byte) 0x5c, (byte) 0x9a, (byte) 0x12,

            (byte) 0x74, (byte) 0xfa, (byte) 0x18, (byte) 0x29

    }; // Hardcoded salt

    private static final int KEY_LENGTH = 128;

    private static final String ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    public SecurityHandler(String keystorePath, String password, String trustStore)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableEntryException {

        this.trustStorePath = trustStore;
        char[] pwd = password.toCharArray();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        FileInputStream fin = new FileInputStream(keystorePath);
        ks.load(fin, pwd);
        fin.close();
        this.ks = ks;
        Entry entry = this.ks.getEntry("keyRSA", new KeyStore.PasswordProtection(pwd));
        if (entry instanceof PrivateKeyEntry) {
            this.privateKey = (PrivateKeyEntry) entry;

        } else {
            System.err.println("Generate a keytool  and a key pair called keyrsa first");
            System.exit(-1);
        }

    }

    public SecurityHandler(String file, String password, String trustStore, String encryptPass)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableEntryException, InvalidKeySpecException {
        this(file, password, trustStore);
        this.key = generateSymkey(encryptPass.toCharArray());

    }

    private SecretKey generateSymkey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate the key based on the password
        PBEKeySpec keySpec = new PBEKeySpec(password, SALT, 20); // pass, salt, iterations
        SecretKeyFactory kf = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key = kf.generateSecret(keySpec);
        return key;
    }

    public boolean confirmIdentity(String userCert, byte[] nonce, byte[] signedNonce) throws NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException, InvalidKeyException, SignatureException {
        // Create a signature object
        Signature signature = Signature.getInstance("MD5withRSA");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert;
        try (FileInputStream fis = new FileInputStream(userCert)) {
            cert = cf.generateCertificate(fis);
        }

        // Verify the signature with the public key
        signature.initVerify(cert);
        signature.update(nonce);

        return signature.verify(signedNonce);
    }

    public boolean confirmNewIdentity(Certificate clientCert, byte[] nonce, byte[] signedNonce)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Create a signature object
        Signature signature = Signature.getInstance("MD5withRSA");

        // Verify the signature with the public key
        signature.initVerify(clientCert);
        signature.update(nonce);
        return signature.verify(signedNonce);
    }

    public byte[] generateNonce(String user_id) {
        byte[] nonce = new byte[1024];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        return nonce;
    }

    public Certificate sendCertificate() {
        return privateKey.getCertificate();
    }

    public byte[] signNonce(byte[] nonce) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Create a signature object
        Signature signature = Signature.getInstance("MD5withRSA");

        // Initialize the signature with the private key
        signature.initSign(privateKey.getPrivateKey());

        // Update the signature with the nonce data
        signature.update(nonce);

        // Generate the signature
        byte[] signedNonce = signature.sign();
        return signedNonce;
    }

    public void saveEncrypted(String toSave, String filePath) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        // Encrypt file using key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        FileOutputStream fos;

        fos = new FileOutputStream(filePath);

        byte[] fileBytes = cipher.doFinal(toSave.getBytes());

        // Escrever o tamanho dos params na primeira linha
        byte[] params = cipher.getParameters().getEncoded();
        fos.write((params.length + "\n").getBytes());
        // escrever os params
        fos.write(params);
        fos.write(fileBytes);

        fos.close();
    }

    public String readEncrypted(String filePath)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        // Decrypt file using key

        FileInputStream fis = new FileInputStream(filePath);
        CipherInputStream cis = null;
        try {
            // ler os params
            ByteArrayOutputStream paramsBytes = new ByteArrayOutputStream();
            int c;
            while ((c = fis.read()) != '\n' && c != -1) {
                paramsBytes.write(c);
            }
            if (c == -1) {
                return null;
            }
            int paramsLen = Integer.parseInt(paramsBytes.toString());
            byte[] params = new byte[paramsLen];
            fis.read(params);

            AlgorithmParameters p = AlgorithmParameters.getInstance(ALGORITHM);
            p.init(params);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, p);
            cis = new CipherInputStream(fis, cipher);

            BufferedReader reader = new BufferedReader(new InputStreamReader(cis));
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                fileContent.append(line).append("\n"); // Append newline character to preserve line breaks
            }
            return fileContent.toString();
        } finally {
            if (cis != null) {
                cis.close();
            }
            fis.close();
        }
    }

    public synchronized String verifyIntegrity(String file)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException, ClassNotFoundException {

        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(fis);
        String isValid = "nValid";

        try {
            // le o conteudo atual do ficheiro
            Object data_object = ois.readObject();
            if (!(data_object instanceof String)) {
                System.out.println("error");
                return (isValid);
            }

            String data = (String) data_object;

            // le o hash do conteudo original
            Object ori_data_object = ois.readObject();
            if (!(data_object instanceof byte[])) {
                System.out.println("error");
                return (isValid);
            }

            byte ori_data[] = (byte[]) ori_data_object;

            // cria um mac e gera um novo hash para o conteudo atual
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(key);
            byte buf[] = data.getBytes();
            mac.update(buf);

            // se o hash do conteudo atual == ao hash do conteudo original
            // significa que o ficheiro nao foi alterado e nao esta comprometido
            if (Arrays.equals(ori_data, mac.doFinal())) {
                isValid = data;
            }

        } finally {
            ois.close();
            fis.close();
        }
        return isValid;

    }

    public void writeHmacFile(String data, String file)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        FileOutputStream fos = new FileOutputStream(file);
        ObjectOutputStream oos = new ObjectOutputStream(fos);

        // cria um mac e gera um novo hash para o conteudo atual
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        byte buf[] = data.getBytes();
        mac.update(buf);

        // escreve no ficheiro a nova informação e o correspondente hash
        oos.writeObject(data);
        oos.writeObject(mac.doFinal());

        fos.close();
        oos.close();

    }

}
