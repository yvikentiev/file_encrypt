package org.example;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: FileEncryptorWithKey <encrypt/decrypt> <inputFile> <outputFile> <keyFile>");
            return;
        }

        String operation = args[0];
        String inputFile = args[1];
        String outputFile = args[2];
        String keyFile = args[3];

        try {
            SecretKey secretKey;

            if ("encrypt".equalsIgnoreCase(operation)) {
                secretKey = generateSecretKey();
                saveSecretKeyToFile(secretKey, keyFile);
                encryptFile(inputFile, outputFile, secretKey);
                System.out.println("Encryption completed.");
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                secretKey = loadSecretKeyFromFile(keyFile);
                decryptFile(inputFile, outputFile, secretKey);
                System.out.println("Decryption completed.");
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static void saveSecretKeyToFile(SecretKey secretKey, String keyFile) throws IOException {
        try (ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(keyFile))) {
            outputStream.writeObject(secretKey);
            System.out.println("Key saved to " + keyFile);
        }
    }

    private static SecretKey loadSecretKeyFromFile(String keyFile) throws IOException, ClassNotFoundException {
        try (ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(keyFile))) {
            return (SecretKey) inputStream.readObject();
        }
    }

    private static void encryptFile(String inputFile, String outputFile, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
            cipherOutputStream.close();
        }
    }

    private static void decryptFile(String inputFile, String outputFile, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }
}
