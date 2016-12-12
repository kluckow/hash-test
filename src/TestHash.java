import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

public class TestHash {

    // The following constants may be changed without breaking existing hashes
    public static final int SALT_BYTE_SIZE = 12;
    public static final int HASH_BYTE_SIZE = 24;
    public static final int PBKDF2_ITERATIONS = 1403;

    public static void main(final String[] args)
        throws Exception {

        // entered password
        final String passwort = "geheim";
        final String hash = createHash(passwort);
        System.err.println("hash: " + hash);

        final boolean ok = validatePassword("geheim", hash);
        System.err.println("result: " + ok);

    }

    // better: PBKDF2WithHmacSHA512 needs Java Cryptography Extension (JCE) Unlimited Strength
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";

    // public static final int ITERATION_INDEX = 1;
    public static final int SALT_INDEX = 0;
    public static final int PBKDF2_INDEX = 1;

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param password the password to hash
     * @return a salted PBKDF2 hash of the password
     */
    public static String createHash(final String password)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        return createHash(password.toCharArray());
    }

    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param password the password to hash
     * @return a salted PBKDF2 hash of the password
     */
    public static String createHash(final char[] password)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Generate a random salt
        final String randomSalt = getRndSalt();

        // TODO: remove, was just for testing
        System.out.println("rndSalt: " + toBase64(randomSalt.getBytes()));

        final byte[] hash = pbkdf2(password, randomSalt.getBytes(),
            PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
        return toBase64(randomSalt.getBytes()) + ":" + toBase64(hash);
    }

    /**
     * Validates a password using a hash.
     *
     * @param password the password to check
     * @param correctHash the hash of the valid password
     * @return true if the password is correct, false if not
     */
    public static boolean validatePassword(final String password, final String correctHash)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        return validatePassword(password.toCharArray(), correctHash);
    }

    /**
     * Validates a password using a hash.
     *
     * @param password the password to check
     * @param correctHash the hash of the valid password
     * @return true if the password is correct, false if not
     */
    public static boolean validatePassword(final char[] password, final String correctHash)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Decode the hash into its parameters
        final String[] params = correctHash.split(":");
        final int iterations = PBKDF2_ITERATIONS;
        final byte[] salt = fromBase64(params[SALT_INDEX]);
        final byte[] hash = fromBase64(params[PBKDF2_INDEX]);
        // Compute the hash of the provided password, using the same salt,
        // iteration count, and hash length
        final byte[] testHash = pbkdf2(password, salt, iterations,
            hash.length);
        // Compare the hashes in constant time. The password is correct if
        // both hashes match.
        return slowEquals(hash, testHash);
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison
     * method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param a the first byte array
     * @param b the second byte array
     * @return true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(final byte[] a, final byte[] b) {

        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * Computes the PBKDF2 hash of a password.
     *
     * @param password the password to hash.
     * @param salt the salt
     * @param iterations the iteration count (slowness factor)
     * @param bytes the length of the hash to compute in bytes
     * @return the PBDKF2 hash of the password
     */
    private static byte[] pbkdf2(final char[] password, final byte[] salt, final int iterations, final int bytes)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        final PBEKeySpec spec = new PBEKeySpec(password, salt,
            iterations, bytes * 8);
        final SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }

    /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param hex the hex string
     * @return the hex string decoded into a byte array
     */
    private static byte[] fromBase64(final String hex) {

        return DatatypeConverter.parseBase64Binary(hex);
    }

    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param array the byte array to convert
     * @return a length*2 character string encoding the byte array
     */
    private static String toBase64(final byte[] array) {

        return DatatypeConverter.printBase64Binary(array);
    }

    public static String getRndSalt() {

        final SecureRandom random = new SecureRandom();
        final byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);
        return toBase64(salt);
    }

}
