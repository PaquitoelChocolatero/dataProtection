import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Test_RSA {
	
	public static void main(String[] args) throws Exception {
		RSALibrary.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
		
		try (Scanner scn = new Scanner(System.in)) {
			System.out.println("Introduzca texto para las pruebas:");
			String plainText = scn.nextLine();
			byte[] cipherText = RSALibrary.encrypt(plainText.getBytes(), publicKey);
			System.out.println("\nTexto cifrado (Codificado en Base64):\n" + Base64.getEncoder().encodeToString(cipherText));
			System.out.println("\nTexto cifrado descrifrado:\n" + new String(RSALibrary.decrypt(cipherText, privateKey)));
			byte[] signature = RSALibrary.sign(plainText.getBytes(), privateKey);
			System.out.println("\nFirma del texto plano (Codificada en Base64):\n" + Base64.getEncoder().encodeToString(signature));
			System.out.println("\nVerificación de firma: " + RSALibrary.verify(plainText.getBytes(), signature, publicKey));
		}

	
	}
}
