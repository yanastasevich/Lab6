import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SimpleSymmetricExampleTest {


    @ParameterizedTest
    @CsvSource({"plainText"})
    public void testConvertToHexadecimal(String plainText){

        String expectedMessage = Utils.toHex("706c61696e54657874".getBytes(StandardCharsets.UTF_8));
        String actualMessage = Utils.toHex(SimpleSymmetricExample.convertPlaintextToHexadecimal(plainText));

        assertTrue(actualMessage.contains(expectedMessage),
                "Actual plain text: " + expectedMessage + " contains expected plain text: " +
                        actualMessage);
    }

    @ParameterizedTest
    @CsvSource({"celebration"})
    public void testEncryptionAndDecryptionOfMessage1(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"censorship"})
    public void testEncryptionAndDecryptionOfMessage2(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"precision"})
    public void testEncryptionAndDecryptionOfMessage3(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"volunteer"})
    public void testEncryptionAndDecryptionOfMessage4(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"implicit"})
    public void testEncryptionAndDecryptionOfMessage5(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"identification"})
    public void testEncryptionAndDecryptionOfMessage6(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"reproduction"})
    public void testEncryptionAndDecryptionOfMessage7(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + expectedPlaintext + " contains expected plain text: " +
                actualPlaintext);
    }
}
