import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SimpleSymmetricTest {

    @ParameterizedTest
    @CsvSource({"celebration"})
    public void testEncryptionAndDecryptionOfMessage1(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        System.out.println("expected plain text " + expectedPlaintext);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"censorship"})
    public void testEncryptionAndDecryptionOfMessage2(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"precision"})
    public void testEncryptionAndDecryptionOfMessage3(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"volunteer"})
    public void testEncryptionAndDecryptionOfMessage4(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"implicit"})
    public void testEncryptionAndDecryptionOfMessage5(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"identification"})
    public void testEncryptionAndDecryptionOfMessage6(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource({"reproduction"})
    public void testEncryptionAndDecryptionOfMessage7(String key) throws NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String expectedPlaintext = "There was a leak in the boat. Nobody had yet noticed it, and nobody would for the next couple of hours.";

        String cipherText = SimpleSymmetric.encrypt(expectedPlaintext, key);
        String actualPlaintext = SimpleSymmetric.decrypt(cipherText, key);

        assertEquals(actualPlaintext, expectedPlaintext, "Actual plain text: " + actualPlaintext + " contains expected plain text: " +
                expectedPlaintext);
    }
}
