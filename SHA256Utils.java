import java.security.MessageDigest;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.HashSet;
import java.security.*;
import java.util.Set;

public class SHA256Utils {

  public static byte[] myKey = new byte[200]; // Ciphertext byte array
  public static byte[] myKeyS = new byte[200]; // Ciphertext byte array Saved
  public static byte[] shrtKey = new byte[200]; // Short key byte array.
  public static int COUNT = 0;

  public static final int INDEX_COUNT = 3;
  public static final int MAX_INDEX = 32; // SHA-512 has 32 bytes

  public static byte XOR(char a, char b, String base) {
    try {
      // Hash the base string using SHA-512
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      byte[] hash = digest.digest(base.getBytes("UTF-8"));

      // Derive unique indices into the hash
      Set<Integer> indexSet = new LinkedHashSet<>();
      int seed = base.hashCode();

      for (int i = 0; indexSet.size() < INDEX_COUNT; i++) {
        int candidate = Math.floorMod(seed + i * 31, MAX_INDEX);
        indexSet.add(candidate);
      }

      // Convert set to array
      int[] indices = indexSet.stream().mapToInt(Integer::intValue).toArray();

      // Use selected hash bytes as XOR masks
      byte mask1 = hash[indices[0]];
      byte mask2 = hash[indices[1]];
      byte mask3 = hash[indices[2]];

      // Apply three rounds of XOR with masks
      byte aX = (byte) (((a ^ mask1) ^ mask2) ^ mask3);
      byte bX = (byte) (((b ^ mask1) ^ mask2) ^ mask3);

      // Final XOR to combine the results
      return (byte) (aX ^ bX);
    } catch (Exception ex) {
      throw new RuntimeException("Error computing XOR: " + ex.getMessage(), ex);
    }
  }

  public static void getBlockCount(String base) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      byte[] hash = digest.digest(base.getBytes("UTF-8"));
      COUNT = (hash[0] & 0xFF) | ((hash[1] & 0xFF) << 8);
      COUNT = Math.max(COUNT, 8);
    } catch (Exception ex) {
      throw new RuntimeException("Failed to generate block count", ex);
    }
  }

  public static void sha256(String base) {
    try {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] hash = digest.digest(base.getBytes("UTF-8"));

    for (int i = 0; i < hash.length; i++) {
      myKey[i] = hash[i];
      myKeyS[i] = hash[i];
    }
    } catch (Exception ex) {
    throw new RuntimeException(ex);
    }
  }

  public static void sha256Short(String base) {
    try {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] hash = digest.digest(base.getBytes("UTF-8"));

    for (int i = 0; i < hash.length; i++) {
      shrtKey[i] = hash[i];
    }
    } catch (Exception ex) {
    throw new RuntimeException(ex);
    }
  }

  // Implementing Fisher–Yates shuffle
  static void shuffleArray(int[] ar) {
    Random rnd = new SecureRandom();
    for (int i = ar.length - 1; i > 0; i--) {
    int index = rnd.nextInt(i + 1);
    // Simple swap
    int a = ar[index];
    ar[index] = ar[i];
    ar[i] = a;
    }
  }
}
