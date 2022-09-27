import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class SimpleSec {
    public static void main(String[] args) throws Exception {
        File privKey = null, pubKey = null, srcFile = null, destFile = null;
        switch(args[0]) {
            case "g":
                RSALibrary.generateKeys();
                try {
                    Scanner scn = new Scanner(System.in);
                    System.out.println("Enter private key passphrase:");
                    final String passphrase = scn.nextLine();
                    scn.close();

                    SymmetricCipher cipher = new SymmetricCipher();
                    privKey = Paths.get("./private.key").toFile();
                    pubKey = Paths.get("./public.key").toFile();

                    byte[] ciphered = cipher.encryptCBC(Files.readAllBytes(privKey.toPath()), passphrase.getBytes());
                    Files.write(privKey.toPath(), ciphered, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                } catch (InvalidKeyException e) {
                    System.err.println(e.getMessage());
                    System.err.println("Desired length: 16 characters");
                    break;
                }
                break;
            case "e":
                if(args.length != 3) {
                    System.err.println("Invalid arguments, usage:\njava SimpleSec command [sourceFile] [destinationFile]");
                    break;
                }
                try {
                    privKey = Paths.get("./private.key").toFile();
                    pubKey = Paths.get("./public.key").toFile();
                } catch (Exception e) {
                    System.err.println("Missing RSA Pair");
                    break;
                }
                try {
                    srcFile = Paths.get(args[1]).toFile();
                    destFile = Paths.get(args[2]).toFile();
                } catch (Exception e) {
                    System.err.println("Wrong source/dest path");
                    System.err.println("java SimpleSec command [sourceFile] [destinationFile]");
                    break;
                }
                if(!privKey.exists() || privKey.isDirectory() || !pubKey.exists() || pubKey.isDirectory()) {
                    System.err.println("Missing RSA Pair");
                    break;
                }
                if(!srcFile.exists() || srcFile.isDirectory()) {
                    System.err.println("Missing source file");
                    break;
                }

                try(Scanner scn = new Scanner(System.in)) {
                    // System.out.println("Enter private key passphrase:");
                    // final String passphrase = scn.nextLine();
                    // SymmetricCipher cipher = new SymmetricCipher();

                    // PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(cipher.decryptCBC(Files.readAllBytes(privKey.toPath()), passphrase.getBytes())));
                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(pubKey.toPath())));
                    SymmetricCipher cipher = new SymmetricCipher();
                    SecureRandom random = new SecureRandom();
                    byte[] rndKey = new byte[16];
                    random.nextBytes(rndKey);
                    byte[] ciphered = cipher.encryptCBC(Files.readAllBytes(srcFile.toPath()), rndKey);
                    
                    byte[] ciphKey = RSALibrary.encrypt(rndKey, publicKey);
                    Files.write(destFile.toPath(), ciphKey, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                    Files.write(destFile.toPath(), ciphered, StandardOpenOption.APPEND);
                }
                break;
                
            case "d":
                if(args.length != 3) {
                    System.err.println("Invalid arguments, usage:\njava SimpleSec command [sourceFile] [destinationFile]");
                    break;
                }
                try {
                    privKey = Paths.get("./private.key").toFile();
                    pubKey = Paths.get("./public.key").toFile();
                } catch (Exception e) {
                    System.err.println("Missing RSA Pair");
                    break;
                }
                try {
                    srcFile = Paths.get(args[1]).toFile();
                    destFile = Paths.get(args[2]).toFile();
                } catch (Exception e) {
                    System.err.println("Wrong source/dest path");
                    System.err.println("java SimpleSec command [sourceFile] [destinationFile]");
                    break;
                }
                if(!privKey.exists() || privKey.isDirectory() || !pubKey.exists() || pubKey.isDirectory()) {
                    System.err.println("Missing RSA Pair");
                    break;
                }
                if(!srcFile.exists() || srcFile.isDirectory()) {
                    System.err.println("Missing source file");
                    break;
                }

                try(Scanner scn = new Scanner(System.in)) {
                    System.out.println("Enter private key passphrase:");
                    final String passphrase = scn.nextLine();
                    SymmetricCipher cipher = new SymmetricCipher();
                    byte[] srcData = Files.readAllBytes(srcFile.toPath());
                    
                    byte[] data = Arrays.copyOfRange(srcData,128, srcData.length);

                    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(cipher.decryptCBC(Files.readAllBytes(privKey.toPath()), passphrase.getBytes())));
                    byte[] decipherKey = RSALibrary.decrypt(Arrays.copyOfRange(srcData, 0, 128), privateKey);



                    byte[] deciphered = cipher.decryptCBC(data, decipherKey);
                    Files.write(destFile.toPath(), deciphered, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                }
                break;

            
        }
    }
}