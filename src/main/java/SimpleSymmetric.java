import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Random;

/**
 * Basic symmetric encryption example
 */
public class SimpleSymmetric {
    public static void main(String[] args) throws Exception {

        String inputString = "And once the hour of christmas had arrived, the eager students realized that life is indeed too short for cryptography.";

        System.out.println("input: "+inputString);

        String keyString = getRandomWordFromDictionary();

        System.out.println("key: " + keyString);

        // decryption pass

        String cipherString = encrypt(inputString, keyString);
        decrypt(cipherString, keyString);
    }

    public static String getRandomWordFromDictionary() throws IOException {
        Random random = new Random();
        String randomWord = "";
        int randomIndex = random.nextInt(25486);
        int wordCounter = 0;
        BufferedReader br = new BufferedReader(new FileReader("words.txt"));
        try {
            StringBuilder sb = new StringBuilder();

            while (wordCounter <= randomIndex) {
                wordCounter++;
                if (wordCounter == randomIndex) {
                    randomWord = br.readLine();
                    randomWord = "0" + randomWord.replace("i", "1") + "1";
                } else br.readLine();
            }
        } finally {
            br.close();
        }
        return randomWord;
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
        return Cipher.getInstance("Blowfish/ECB/PKCS5Padding", provider);
    }

    private static void initializeCipher(Cipher cipher, byte[] keyBytes, int mode) throws InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "Blowfish");
        cipher.init(mode, keySpec);
    }

    // method contents from suggestion by Paul Klingberg on Moodle
    public static byte[] encodeKeys(String key) throws NoSuchAlgorithmException {
        Charset charset = StandardCharsets.US_ASCII;
        MessageDigest keySHA256 = MessageDigest.getInstance("SHA-256");
        return keySHA256.digest(key.getBytes(charset));
    }
}
