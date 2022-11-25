
/**
 * General utilities for the second chapter examples.
 */
public class Utils {
    private static String digits = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data   the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        System.out.println("To HEX STARTED");
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {

            int v = data[i] & 0xff;
            System.out.println("Appending " + digits.charAt(v >> 4) + digits.charAt(v & 0xf) + " from " + data[i] + "(" + v + ")");

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    public static byte[] stringToBytes(String data, int length) {
        System.out.println("To HEX STARTED");
        StringBuffer buf = new StringBuffer(data);
        byte[] hexaBytes = new byte[length];

        for (int i = 0; i != length; i++) {


            String hex = String.format("%04x", (int) buf.charAt(i));
            hexaBytes[i] = 0;
            int v = buf.charAt(i) & 0xff;
            System.out.println("Appending " + hex + " from " + buf.charAt(i) + "(" + v + ")");

        }

        return hexaBytes;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static byte[] stringToBytes(String data) {
        return hexStringToByteArray(data);
    }
}
