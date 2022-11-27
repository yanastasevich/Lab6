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

        String inputString = "This is a test message.";
        Charset charset = StandardCharsets.US_ASCII;
        byte[] input = inputString.getBytes(charset);

        // from moodle forum suggestion
        String keyString = "testkey";

        String cipherString = "70ce735916f59447ef721b8cb0bf8cf66fbb29c0ef97ab714bb3a4630dabcc74";

        byte[] cipherInput = hexToByteArray(cipherString);

        System.out.println("key: " + keyString);

        // decryption pass

        encrypt(input, keyString);
        decrypt(cipherInput, keyString);
    }

    // method for converting hex to byte array using parseInt()
    // https://www.geeksforgeeks.org/java-program-to-convert-hex-string-to-byte-array/
    private static byte[] hexToByteArray(String hex) {
        byte[] data = new byte[hex.length() / 2];

        for (int i = 0; i < data.length; i++) {
            int index = i * 2;
            int val = Integer.parseInt(hex.substring(index, index + 2), 16);
            data[i] = (byte) val;
        }

        return data;
    }

    private static String encrypt(byte[] input, String key) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        byte[] keyBytes = encodeKeys(key);
        Security.addProvider(new BouncyCastleProvider());

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");


        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        System.out.println("");


        return Utils.toHex(cipherText);
    }

    public static String decrypt(byte[] cipherText, String keyString) throws ShortBufferException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        Charset charset = StandardCharsets.US_ASCII;
        byte[] keyBytes = encodeKeys(keyString);


        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        byte[] plainText = new byte[cipherText.length];

        int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        String plainTextString = new String(plainText, charset);

        System.out.println("plain text : " + plainTextString + " bytes: " + ptLength);

        return plainTextString;
    }

    public static byte[] encodeKeys(String key) throws NoSuchAlgorithmException {
        Charset charset = StandardCharsets.US_ASCII;
        MessageDigest keySHA256 = MessageDigest.getInstance("SHA-256");
        return keySHA256.digest(key.getBytes(charset));
    }
}
