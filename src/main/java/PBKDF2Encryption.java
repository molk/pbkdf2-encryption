import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PBKDF2Encryption {

    private static final String PASSWORD = "34E6E04D-8A67-4B0A-9426-4AF9104E67B0";

    private static final int KEY_SIZE_BITS = 256;
    private static final int SALT_SIZE     = 32;
    private static final int IV_SIZE       = 16; // fixed AES Block Size

    private static final int DERIVATION_ITERATIONS  = 1000;

    /**
     * <- plain text
     * -> base64 encoded string: salt-value + iv + encrypted-text
     */
    public static String encryptAndEncode(String text) {
        try {
            EncryptedValue encryptedValue = encrypt(text);

            return asString(Base64.getEncoder().encode(encryptedValue.bytes()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * <- base64 encoded string: salt-value + iv + encrypted-text
     * -> plain text
     */
    public static String decodeAndDecrypt(String encryptedBase64) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(asBytes(encryptedBase64));

            return decrypt(EncryptedValue.of(encrypted));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static EncryptedValue encrypt(String text) {
        try {
            byte[] salt       = randomBytes(SALT_SIZE);
            byte[] iv         = randomBytes(IV_SIZE);
            Cipher cipher     = cipher(Cipher.ENCRYPT_MODE, salt, iv);
            byte[] encrypted  = cipher.doFinal(asBytes(text));

            return EncryptedValue.of(salt, iv, encrypted);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(EncryptedValue encryptedValue) {
        try {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, encryptedValue.salt, encryptedValue.iv);
            byte[] decrypted = cipher.doFinal(encryptedValue.encryptedText);

            return asString(decrypted);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Cipher cipher(int mode, byte[] salt, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, key(salt), new IvParameterSpec(iv));

        return cipher;
    }

    private static Key key(byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(PASSWORD.toCharArray(), salt, DERIVATION_ITERATIONS, KEY_SIZE_BITS);
        byte[] secretKey = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(secretKey, "AES");
    }

    private static byte[] randomBytes(int size) {
	    byte[] randomBytes = new byte[size];
	    new SecureRandom().nextBytes(randomBytes);
	    return randomBytes;
    }

    private static String asString(byte[] bytes) {
        return new String(bytes, UTF_8);
    }

    private static byte[] asBytes(String str) {
        return str.getBytes(UTF_8);
    }

    public static class EncryptedValue {

        public final byte[] salt;
        public final byte[] iv;
        public final byte[] encryptedText;

        public static EncryptedValue of(byte[] salt, byte[] iv, byte[] encryptedText) {
            return new EncryptedValue(salt, iv, encryptedText);
        }

        public static EncryptedValue of(byte[] bytes) {
            return new EncryptedValue(
                Arrays.copyOfRange(bytes, 0                   , SALT_SIZE),
                Arrays.copyOfRange(bytes, SALT_SIZE           , SALT_SIZE + IV_SIZE),
                Arrays.copyOfRange(bytes, SALT_SIZE + IV_SIZE , bytes.length));
        }

        private EncryptedValue(
                final byte[] salt,
                final byte[] iv,
                final byte[] encryptedText
            ) {
            this.salt          = salt;
            this.iv            = iv;
            this.encryptedText = encryptedText;
        }

        public byte[] bytes() {
            try {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

                outputStream.write(salt);
                outputStream.write(iv);
                outputStream.write(encryptedText);

                return outputStream.toByteArray();
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toString() {
            return String.format("salt=%s, iv=%s, text=%s", toHex(salt), toHex(iv), toHex(encryptedText));
        }

        private static String toHex(byte[] array) {
            return String.format("%032X", new BigInteger(1, array));
        }
    }

}
