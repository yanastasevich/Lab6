import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SimpleSymmetricExampleTest {


    @ParameterizedTest
    @CsvSource({"plainText"})
    public void testConvertToHexadecimal(String plainText){

        String expectedMessage = Utils.toHex("706c61696e54657874".getBytes(StandardCharsets.UTF_8));
        String actualMessage = Utils.toHex(SimpleSymmetricExample.convertPlaintextToHexadecimal(plainText));

        assertTrue(actualMessage.equals(expectedMessage),
                "Actual plain text: " + expectedMessage + " contains expected plain text: " +
                        actualMessage);



    }
}
