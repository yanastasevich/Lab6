
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Basic symmetric encryption example
 */
public class SimpleSymmetric
{
    public static void main(
            String[]    args)
            throws Exception
    {

        String inputString = "This is a test message.";
        Charset charset = Charset.forName("ASCII");
        byte[] input = inputString.getBytes(charset);

        // from moodle forum suggestion
        String keyString = "Factor";
        MessageDigest keySHA256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = keySHA256.digest(keyString.getBytes(charset));

        String cipherString = "7a3788d1e91a230e940cd31ab71a6a8f";

        byte[] cipherInput = HexToByteArray(cipherString);


        //SecretKeySpec key = new SecretKeySpec(pbeKey.getEncoded(), "AES");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        System.out.println("key: " + keyString);

        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");

        System.out.println("input text : " + inputString);

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        System.out.println("");

        // decryption pass

        System.out.println("key: " + keyString);

        System.out.println("cipher text: " + cipherString);

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] plainText = new byte[cipherInput.length];

        int ptLength = cipher.update(cipherInput, 0, cipherInput.length, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        String plainTextString = new String(plainText, charset);

        System.out.println("plain text : " + plainTextString + " bytes: " + ptLength);
    }

    // method for converting hex to byte array using parseInt()
    // https://www.geeksforgeeks.org/java-program-to-convert-hex-string-to-byte-array/
    private static byte[] HexToByteArray(String hex) {
        byte[] data = new byte[hex.length()/2];

        for (int i = 0; i < data.length; i++) {
            int index = i * 2;
            int val = Integer.parseInt(hex.substring(index, index + 2), 16);
            data[i] = (byte)val;
        }

        return data;
    }
}


