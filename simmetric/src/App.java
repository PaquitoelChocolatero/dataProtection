import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class App {
    public static void main(String[] args) {
        SymmetricCipher mCipher = new SymmetricCipher();
        IvParameterSpec iv = new IvParameterSpec(mCipher.iv);
        SecretKeySpec key = new SecretKeySpec(mCipher.iv, "AES");
        byte[] value = "ciruela12345678901234567".getBytes();

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(value);
            byte[] mEncrypted = mCipher.encryptCBC(value, mCipher.iv);
            System.out.println(Base64.getEncoder().encodeToString(encrypted));
            System.out.println(Base64.getEncoder().encodeToString(mEncrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
}