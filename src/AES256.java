//Import these built-in and user-defined packages to facilitate this encryption source code.
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

//Please install the JCE policy for unlimited strength jurisdiction since 256-bit key size cannot run in restricted
//JCE strength.
//You may refer this link for more info:
// https://deveshsharmablogs.wordpress.com/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/
//If we have not installed the JCE we will be getting the error like “java.security.InvalidKeyException: Illegal key size”
// or “org.apache.xml.security.encryption.XMLEncryptionException: Illegal key size or default parameters”

public class AES256 {

    //Initialization Vector or IV is a pseudorandom fixed size input used for encryption and decryption.
    public static String initVector = "0123456789012345";

    //Encryption and Decryption must use the same secret key and the salt String for letting both sender and
    // receivers to know.
    //Salt string is added for hashing purposes.
    // It is fixed-length cryptographically-strong random value that is added to the input of hash functions
    // to create unique hashes for every input. Salt increases the security of the encrypted passwords.
    //The secret key should be 32-byte length or 256-bit length similar to 32 characters.
    private static String secretKey = "BewareOfHackersMyFriends!!!!!!!!";
    private static String salt = "bruteforceattack!!";

    public static String Encryption(String strToEncrypt, String secret)
    {
        try
        {
            // AES encrypts passwords of 128 bits equivalent to 16 bytes. The bytes are stored in an array form.
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //PBKDF2WithHmacSHA256 is the password hashing built-in interface.
            //The secret key size for this AES is 256 bits.
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Base64 encoding in UTF-8 charset is used for storing and validating data in byte format.
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String Decryption(String strToDecrypt, String secret) {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    // The output will display the AES 256-bit key length encryption and decryption output.
    public static void main(String[] args)
    {
        String originalString = "vickymario73@gmail.com";

        String encryptedString = AES256.Encryption(originalString, secretKey) ;
        String decryptedString = AES256.Decryption(encryptedString, secretKey) ;

        System.out.println("Original String: "+ originalString);
        System.out.println("Encrypted String(Base64 format): "+encryptedString);
        System.out.println("Decrypted String: "+decryptedString);
    }
}
