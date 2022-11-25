
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;


/**
 * Basic symmetric encryption example
 */
public class SimpleSymmetricExample {
    public static void main(String[] args) throws Exception {

        // bytes that are in hexadecimal
        byte[] input = Utils.hexStringToByteArray("0f54bbe30797778ca31d2b4280ea1e780eb7282cd3014b095206d5906e36ba1cff633565e879f949ae4c14cce2532716");

        System.out.println("input: " + input);
        byte[] keyBytes = convertPlaintextToHexadecimal("Computergrafik");

        System.out.println("key: " + keyBytes.length);
        //TODO: go into classes
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        System.out.println("key key spec: " + key);

        // done by Yana
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        System.out.println("kwwy text : " + Utils.toHex(keyBytes));

        System.out.println("input text : " + Utils.toHex(input));

        // encryption pass

        String cipherText = encrypt(input, cipher, key);
        System.out.println("encryption: " + cipherText);

        // decryption pass

        String plainText = decrypt(cipher, input, cipherText.getBytes(StandardCharsets.UTF_8), key);
        System.out.println("decryption: " + plainText);
    }

    private static String encrypt(byte[] input, Cipher cipher, SecretKeySpec key) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] cipherText = new byte[input.length];

        cipher.init(Cipher.ENCRYPT_MODE, key);

        int ctLength = getCipherLength(cipher, input, cipherText);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher text: " + Arrays.toString(cipherText) + " bytes: " + ctLength);


        return Utils.toHex(cipherText);
    }

    private static String decrypt(Cipher cipher, byte[] input, byte[] cipherText, SecretKeySpec key) throws ShortBufferException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int cipherTextLength = getCipherLength(cipher, input, cipherText);
        byte[] plainText = new byte[cipherTextLength];

        cipher.init(Cipher.DECRYPT_MODE, key);

        int ptLength = cipher.update(cipherText, 0, cipherTextLength, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + ptLength);

        return Utils.toHex(plainText);
    }

    private static int getCipherLength(Cipher cipher, byte[] input, byte[] cipherText) throws ShortBufferException {
        return cipher.update(input, 0, input.length, cipherText, 0);
    }

    // TODO: write a function that convert letters to hexadecimal convertiert


    public static byte[] convertPlaintextToHexadecimal(String plaintext) {
        StringBuilder cipherText = new StringBuilder();
        char[] characterList = plaintext.toCharArray();

        for (char character : characterList) {
            cipherText.append(Integer.toHexString(character));
        }
        System.out.println("Da result"+cipherText.toString());
        return Utils.hexStringToByteArray(cipherText.toString());
    }

}
