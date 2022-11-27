import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Basic symmetric encryption example
 */
public class SimpleSymmetric {
    public static void main(String[] args) throws Exception {

        String inputString = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String keyString = "celebration";

        System.out.println("key: " + keyString);

        // decryption pass

        String cipherString = encrypt(inputString, keyString);
        decrypt(cipherString, keyString);
    }


    static String encrypt(String plainTextString, String key) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Charset charset = StandardCharsets.US_ASCII;
        byte[] plainTextBytes = plainTextString.getBytes(charset);

        Cipher cipher = getCipherForAProvider("BC");
        byte[] keyBytes = encodeKeys(key);
        initializeCipher(cipher, keyBytes, Cipher.ENCRYPT_MODE);

        byte[] cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
        int ctLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);

        return Utils.toHex(cipherText);
    }

    public static String decrypt(String cipherTextString, String keyString) throws ShortBufferException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] cipherTextBytes = Utils.stringToBytes(cipherTextString);

        Cipher cipher = getCipherForAProvider("BC");
        byte[] keyBytes = encodeKeys(keyString);
        initializeCipher(cipher, keyBytes, Cipher.DECRYPT_MODE);


        byte[] plainText = new byte[cipherTextBytes.length];
        int ptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        Charset charset = StandardCharsets.US_ASCII;
        String plainTextString = new String(plainText, charset);
        System.out.println("plain text : " + plainTextString + " bytes: " + ptLength);

        return plainTextString.trim();
    }

    private static Cipher getCipherForAProvider(String provider) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        return Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
    }

    private static void initializeCipher(Cipher cipher, byte[] keyBytes, int mode) throws InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        cipher.init(mode, keySpec);
    }

    // method contents from suggestion by Paul Klingberg on Moodle
    public static byte[] encodeKeys(String key) throws NoSuchAlgorithmException {
        Charset charset = StandardCharsets.US_ASCII;
        MessageDigest keySHA256 = MessageDigest.getInstance("SHA-256");
        return keySHA256.digest(key.getBytes(charset));
    }
}
