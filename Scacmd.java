import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Random;
import java.lang.*;
import java.io.Console;

public final class Scacmd {

   public static final int EOF = -1;     // end of file
   public static InputStream in = null;   // input file
   public static OutputStream out = null; // output file
   public static int buffer;           // one character buffer
   public static int N;               // number of input bits left in buffer
   public static int M;               // number of output bits left in buffer
   public static boolean gotInputStream = false;  // got an input file name
   public static boolean gotOutputStream = false;  // got an output file name

   public static String VERSION = "4.3"; // Release version - IMPROVED SECURITY + PASSWORD RULES
   public static int KEY_DIGEST = 32;   // Cipher Key hash size
   public static int BLOCK_SIZE = 55;   // Rubix block size

   public static int keylen = 0;      // Chiper key length
   public static int Z_SIZE = 4000;   // Z array size
   public static int S_SIZE = 4000;   // S array size
   public static int KEY_STRETCH_ITERATIONS = 50000; // Key stretching iterations

   public static byte byteOUT;
   public static byte byteIN;
   public static byte myByte;

   public static String myOutFile = null; // input file name
   public static String myInFile = null; // output file name
   public static Console cnsl = null; // console object for password


   // don't instantiate
   public Scacmd() {
   }

   // NEW: Password strength validation
   public static boolean isStrongPassword(String password) {
      if (password == null || password.length() < 9) {
         return false;
      }
      
      boolean hasUpper = false;
      boolean hasLower = false;
      boolean hasDigit = false;
      
      for (int i = 0; i < password.length(); i++) {
         char c = password.charAt(i);
         if (Character.isUpperCase(c)) hasUpper = true;
         if (Character.isLowerCase(c)) hasLower = true;
         if (Character.isDigit(c)) hasDigit = true;
      }
      
      return hasUpper && hasLower && hasDigit;
   }
   
   public static String getPasswordStrengthError(String password) {
      if (password == null || password.length() < 9) {
         return "Password must be at least 9 characters long.";
      }
      
      boolean hasUpper = false;
      boolean hasLower = false;
      boolean hasDigit = false;
      
      for (int i = 0; i < password.length(); i++) {
         char c = password.charAt(i);
         if (Character.isUpperCase(c)) hasUpper = true;
         if (Character.isLowerCase(c)) hasLower = true;
         if (Character.isDigit(c)) hasDigit = true;
      }
      
      if (!hasUpper) return "Password must contain at least one uppercase letter (A-Z).";
      if (!hasLower) return "Password must contain at least one lowercase letter (a-z).";
      if (!hasDigit) return "Password must contain at least one digit (0-9).";
      
      return null; // Password is strong
   }

   // NEW: Key stretching function to slow down brute force attacks
   public static String stretchKey(String password, int iterations) {
      try {
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] key = password.getBytes("UTF-8");
         
         // Hash it many times to slow down attackers
         for (int i = 0; i < iterations; i++) {
            digest.update(key);
            digest.update(Integer.toString(i).getBytes("UTF-8"));
            key = digest.digest();
         }
         
         // Convert to hex string for use as stretched password
         StringBuilder hexString = new StringBuilder();
         for (int i = 0; i < key.length; i++) {
            String hex = Integer.toHexString(0xff & key[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
         }
         
         return hexString.toString();
      } catch (Exception e) {
         throw new RuntimeException("Key stretching failed", e);
      }
   }

   public static void openFile() {
      try {
         if (gotInputStream) {
            File inFile = new File(myInFile);
            in = new BufferedInputStream(new FileInputStream(inFile));
         } else {
            in = new BufferedInputStream(System.in);
         }

         if (gotOutputStream) {
            File outFile = new File(myOutFile);
            out = new BufferedOutputStream(new FileOutputStream(outFile));
         } else {
            out = new BufferedOutputStream(System.out);
         }
      } catch (FileNotFoundException ex) {
         System.err.println("File not found.");
         System.exit(1);
      }
   }

   public static void clearBuffer() {
      if (M == 0) return;
      if (M > 0) buffer <<= (8 - N);
      try {
         out.write(buffer);
      } catch (IOException e) {
         e.printStackTrace();
      }
      M = 0;
      buffer = 0;
   }

   public static void writeBit(boolean bit) {
      // add bit to buffer
      buffer <<= 1;
      if (bit) buffer |= 1;

      // if buffer is full (8 bits), write out as a single byte
      M++;
      if (M == 8) clearBuffer();
   }

   public static void fillBuffer() {
      try {
         buffer = in.read();
         N = 8;
      } catch (IOException e) {
         System.out.println("EOF");
         buffer = EOF;
         N = -1;
      }
   }

   public static void close() {
      try {
         in.close();
      } catch (IOException e) {
         e.printStackTrace();
         throw new RuntimeException("Could not close BinaryStdIn");
      }
   }

   public static void flush() {
      clearBuffer();
      try {
         out.flush();
      } catch (IOException e) {
         e.printStackTrace();
      }
   }

   public static boolean isEmpty() {
      return buffer == EOF;
   }

   public static char readchar() {
      if (isEmpty()) throw new RuntimeException("Reading from empty input stream");

      // special case when aligned byte
      if (N == 8) {
         int x = buffer;
         fillBuffer();
         return (char) (x & 0xff);
      }

      // combine last N bits of current buffer with first 8-N bits of new buffer
      int x = buffer;
      x <<= (8 - N);
      int oldN = N;
      fillBuffer();
      if (isEmpty()) throw new RuntimeException("Reading from empty input stream");
      N = oldN;
      x |= (buffer >>> N);
      return (char) (x & 0xff);
      // the above code doesn't quite work for the last character if N = 8
      // because buffer will be -1
   }

   public static byte readByte() {
      char c = readchar();
      byte x = (byte) (c & 0xff);
      return x;
   }

   public static void writeByte(int x) {
      assert x >= 0 && x < 256;

      // optimized if byte-aligned
      if (M == 0) {
         try {
            out.write(x);
         } catch (IOException e) {
            e.printStackTrace();
         }
         return;
      }

      // otherwise write one bit at a time
      for (int i = 0; i < 8; i++) {
         boolean bit = ((x >>> (8 - i - 1)) & 1) == 1;
         writeBit(bit);
      }
   }

   public static void write(byte x) {
      writeByte(x & 0xff);
   }

   public static int read(byte[] buffer) {
      int bytesRead = 0;
      for (int i = 0; i < buffer.length; i++) {
         buffer[i] = readByte();  // Use your readByte() method to read one byte at a time
         bytesRead++;
      }
      return bytesRead;  // Return the total number of bytes read
   }

   public static void write(byte[] buffer) {
      for (int i = 0; i < buffer.length; i++) {
         writeByte(buffer[i] & 0xFF);  // Write each byte using the writeByte() method
      }
   }


   // Use environmental VAR for key.
   // Windows:  set CIPHERKEY="f00Bar"
   // UNIX/MAC: export CIPHERKEY=f00Bar

   // MAIN LINE LOGIC
   public static void main(String[] args) {
      String cipherKeyString = null;
      RubiksCubeCipher54 rx = new RubiksCubeCipher54();
      GetOpt go = new GetOpt(args, "vhedm:p:i:o:");
      ArrayA AA = new ArrayA();
      ArrayZ AZ = new ArrayZ();
      ArrayS AS = new ArrayS();
      ArrayH AH = new ArrayH();
      SHA256Utils sha = new SHA256Utils();
      int ch = -1;
      boolean ENC = false;
      boolean DEC = false;
      boolean gotPW = false;
      int BB0 = 0;
      int BB1 = 0;
      int BB2 = 0;
      int BB3 = 0;
      int BB4 = 0;
      int BB5 = 0;
      int BB6 = 0;
      int BB7 = 0;
      int keyCksum = 0;


      // process options in command line arguments
      while ((ch = go.getopt()) != go.optEOF) {
         if ((char) ch == 'v') {
            System.err.println("");
            System.err.println("Scacmd.jar version: " + VERSION);
            System.err.println("Security: Password must have uppercase, lowercase, and digit");
            System.err.println("          50,000 key stretch iterations");
            System.err.println("");
            System.exit(0);
         } else if ((char) ch == 'h') {
            System.err.println("");
            System.err.println("java -jar Scacmd.jar [-v] [-h] [-e|-d] -i inputFile -o outputFile [-p]<cipher key>");
            System.err.println("cat [type] inputFile | java -jar Scacmd.jar [-v] [-h] [-e|-d] [-p]<cipher key> > outputFile");
            System.err.println("");
            System.err.println("Password Requirements:");
            System.err.println("  - Minimum 9 characters");
            System.err.println("  - At least one uppercase letter (A-Z)");
            System.err.println("  - At least one lowercase letter (a-z)");
            System.err.println("  - At least one digit (0-9)");
            System.err.println("");
            System.err.println("Examples: MyDog2024  Coffee5pm  Secure123");
            System.err.println("");
            System.exit(0);
         } else if ((char) ch == 'd') {
            DEC = true;
         } else if ((char) ch == 'e') {
            ENC = true;
         } else if ((char) ch == 'p') {
            cipherKeyString = go.optArgGet();
            if (cipherKeyString.length() < 9) {
               System.err.println("ERROR: Key must be 9 or greater characters");
               System.err.println("       This is required for adequate security.");
               System.exit(1);
            }
            
            // Validate password strength
            String strengthError = getPasswordStrengthError(cipherKeyString);
            if (strengthError != null) {
               System.err.println("ERROR: " + strengthError);
               System.err.println("       Password must contain:");
               System.err.println("         - At least one uppercase letter (A-Z)");
               System.err.println("         - At least one lowercase letter (a-z)");
               System.err.println("         - At least one digit (0-9)");
               System.exit(1);
            }
            
            gotPW = true;
         } else if ((char) ch == 'i') {
            myInFile = go.optArgGet();
            if (myInFile.length() < 1) {
               System.err.println("ERROR: Invalid input file name.");
               System.exit(1);
            } else {
               gotInputStream = true;
            }
         } else if ((char) ch == 'o') {
            myOutFile = go.optArgGet();
            if (myOutFile.length() < 1) {
               System.err.println("ERROR: Invalid output file name.");
               System.exit(1);
            } else {
               gotOutputStream = true;
            }
         } else
            System.exit(1);   // undefined option
      }         // getopt() returns '?'

      if (!gotPW) {
         try {
            cipherKeyString = System.getenv("CIPHERKEY"); // used cipherKey environmental var if set.
            keylen = cipherKeyString.length();
            if (cipherKeyString != null) {
               if (keylen < 9) {
                  System.err.println("ERROR: CIPHERKEY must be 9 or greater characters");
                  cnsl = System.console();
                  if (cnsl != null) {
                     char[] pwd = cnsl.readPassword("Password: ");
                     cipherKeyString = new String(pwd);
                  }
               } else {
                  // Validate environment variable password strength
                  String strengthError = getPasswordStrengthError(cipherKeyString);
                  if (strengthError != null) {
                     System.err.println("ERROR: CIPHERKEY is weak - " + strengthError);
                     System.err.println("       Password must contain uppercase, lowercase, and digit.");
                     cnsl = System.console();
                     if (cnsl != null) {
                        char[] pwd = cnsl.readPassword("Password: ");
                        cipherKeyString = new String(pwd);
                     }
                  }
               }
            }
         } catch (Exception e) {
            try {
               cnsl = System.console();
               if (cnsl != null) {
                  char[] pwd = cnsl.readPassword("Password: ");
                  cipherKeyString = new String(pwd);
               }
            } catch (Exception ex) {
               System.err.println("ERROR: No CIPHERKEY variable found, use -p.");
               System.exit(1);
            }
         }
      }

      // NEW: Final password length and strength check after all input methods
      if (cipherKeyString == null || cipherKeyString.length() < 9) {
         System.err.println("ERROR: Password must be at least 9 characters long.");
         System.err.println("       Weak passwords can be cracked by attackers.");
         System.exit(1);
      }
      
      // Validate password strength
      String strengthError = getPasswordStrengthError(cipherKeyString);
      if (strengthError != null) {
         System.err.println("ERROR: " + strengthError);
         System.err.println("       Password requirements:");
         System.err.println("         - Minimum 9 characters");
         System.err.println("         - At least one uppercase letter (A-Z)");
         System.err.println("         - At least one lowercase letter (a-z)");
         System.err.println("         - At least one digit (0-9)");
         System.err.println("");
         System.err.println("       Examples of valid passwords:");
         System.err.println("         MyDog2024  Coffee5pm  Secure123");
         System.exit(1);
      }

      // NEW: Apply key stretching to slow down brute force attacks
      String originalPassword = cipherKeyString;
      cipherKeyString = stretchKey(cipherKeyString, KEY_STRETCH_ITERATIONS);

      int p = 0;
      int r = 0;
      int q = 0;
      int i = 0;
      int j = 0;
      int k = 0;
      int l = 0;
      int z = 1;
      int I = 1;

      // Check if both -d and -e are chosen or if neither is chosen
      if (ENC == DEC) {
         System.err.println("Choose either -d or -e.");
         System.exit(1);
      }

      // Open inpuit / output files.
      openFile();
      fillBuffer();

      // Shuffle.
      if (ENC) {
         sha.shuffleArray(AA.A);
      }

      // Convert char to byte and store
      byte[] H = new byte[10]; // H[0] is unused, we use indices 1 to 9
      for (I = 1; I < 10; I++) {
         H[I] = (byte) ((char) AA.A[I] & 0xff); // Convert char to byte and store
      }

      // XOR operations on H bytes
      for (I = 1; I < 5; I++) {
         H[I] = sha.XOR((char) H[I], (char) H[9 - I],cipherKeyString);
      }

      // Get first 4 bytes passcode hash(ciphertext) or data(plaintext)
      for (I = 0; I < 4; I++) {
         rx.bytesIN[I] = Scacmd.readByte();
      }

      // Get a 4 digit checksum from cipher key string
      try {
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         byte[] digest = md.digest(cipherKeyString.getBytes("UTF-8"));

         // Use the digest bytes directly instead of converting to string
         int keyCksumValue = 0;
         for (I = 0; I < 4; I++) {
            keyCksumValue = (keyCksumValue << 8) | (digest[I] & 0xFF);
         }
         
         keyCksum = Math.abs(keyCksumValue % (Z_SIZE - 2));
         if (keyCksum >= Z_SIZE - 2 || keyCksum < 0) {
            keyCksum = Math.abs(keyCksumValue % (Z_SIZE / 2));
         }
      } catch (Exception ex) {
         throw new RuntimeException(ex);
      }

      // Create the cipherKey
      if (DEC) {
         // Decrypt the hash bytes.

         int nibble0 = (rx.bytesIN[0] << 4) & 0xf0;
         int nibble1 = (rx.bytesIN[0] >>> 4) & 0x0f;

         int nibble2 = (rx.bytesIN[1] << 4) & 0xf0;
         int nibble3 = (rx.bytesIN[1] >>> 4) & 0x0f;

         int nibble4 = (rx.bytesIN[2] << 4) & 0xf0;
         int nibble5 = (rx.bytesIN[2] >>> 4) & 0x0f;

         int nibble6 = (rx.bytesIN[3] << 4) & 0xf0;
         int nibble7 = (rx.bytesIN[3] >>> 4) & 0x0f;

         rx.bytesIN[0] = (byte) ((nibble1 | nibble0));
         rx.bytesIN[1] = (byte) ((nibble3 | nibble2));
         rx.bytesIN[2] = (byte) ((nibble5 | nibble4));
         rx.bytesIN[3] = (byte) ((nibble7 | nibble6));

         if (cipherKeyString.length() < AH.HH.length) {
            BB0 = AH.HH[(AH.HH[cipherKeyString.length()])];
            BB1 = AH.HH[(AH.HH[cipherKeyString.length() + 1])];
            BB2 = AH.HH[(AH.HH[cipherKeyString.length() + 2])];
            BB3 = AH.HH[(AH.HH[cipherKeyString.length() + 3])];
            BB4 = AH.HH[(AH.HH[cipherKeyString.length() + 4])];
            BB5 = AH.HH[(AH.HH[cipherKeyString.length() + 5])];
            BB6 = AH.HH[(AH.HH[cipherKeyString.length() + 6])];
            BB7 = AH.HH[(AH.HH[cipherKeyString.length() + 7])];
         } else {
            System.err.println("Passkey to large");
            System.exit(1);
         }

         // This returns myKey array
         sha.sha256(cipherKeyString);

         byte byteIN0 = sha.XOR((char) sha.myKey[BB0], (char) sha.myKey[BB4],cipherKeyString);
         byteIN0 = sha.XOR((char) rx.bytesIN[0], (char) byteIN0,cipherKeyString);

         byte byteIN1 = sha.XOR((char) sha.myKey[BB1], (char) sha.myKey[BB5],cipherKeyString);
         byteIN1 = sha.XOR((char) rx.bytesIN[1], (char) byteIN1,cipherKeyString);

         byte byteIN2 = sha.XOR((char) sha.myKey[BB2], (char) sha.myKey[BB6],cipherKeyString);
         byteIN2 = sha.XOR((char) rx.bytesIN[2], (char) byteIN2,cipherKeyString);

         byte byteIN3 = sha.XOR((char) sha.myKey[BB3], (char) sha.myKey[BB7],cipherKeyString);
         byteIN3 = sha.XOR((char) rx.bytesIN[3], (char) byteIN3,cipherKeyString);

         // Make new keyCksum
         int num = (nibble7 << 12) | (nibble6 << 8) | (nibble5 << 4) | (nibble4 << 0);
         keyCksum = (int) (num % (Z_SIZE - 2));
         if (keyCksum > (Z_SIZE - 2) || keyCksum < 0) {
            keyCksum = (int) (num % (Z_SIZE / 2));
         }

         sha.sha256(cipherKeyString + Integer.toString(keyCksum));
      }

      // ENCRYPT only logic.
      if (ENC) {
         // Encrypt and write the hash bytes to ciphertext file.

         if (cipherKeyString.length() < AH.HH.length) {
            BB0 = AH.HH[(AH.HH[cipherKeyString.length()])];
            BB1 = AH.HH[(AH.HH[cipherKeyString.length() + 1])];
            BB2 = AH.HH[(AH.HH[cipherKeyString.length() + 2])];
            BB3 = AH.HH[(AH.HH[cipherKeyString.length() + 3])];
            BB4 = AH.HH[(AH.HH[cipherKeyString.length() + 4])];
            BB5 = AH.HH[(AH.HH[cipherKeyString.length() + 5])];
            BB6 = AH.HH[(AH.HH[cipherKeyString.length() + 6])];
            BB7 = AH.HH[(AH.HH[cipherKeyString.length() + 7])];
         } else {
            System.err.println("Passkey to large");
            System.exit(1);
         }

         // This returns myKey array
         sha.sha256(cipherKeyString);

         byte byteOUT0 = sha.XOR((char) sha.myKey[BB0], (char) sha.myKey[BB4],cipherKeyString);
         byteOUT0 = sha.XOR((char) H[1], (char) byteOUT0,cipherKeyString);
         int nibble0 = (byteOUT0 << 4) & 0xf0;
         int nibble1 = (byteOUT0 >>> 4) & 0x0f;

         byte byteOUT1 = sha.XOR((char) sha.myKey[BB1], (char) sha.myKey[BB5],cipherKeyString);
         byteOUT1 = sha.XOR((char) H[2], (char) byteOUT1,cipherKeyString);
         int nibble2 = (byteOUT1 << 4) & 0xf0;
         int nibble3 = (byteOUT1 >>> 4) & 0x0f;

         byte byteOUT2 = sha.XOR((char) sha.myKey[BB2], (char) sha.myKey[BB6],cipherKeyString);
         byteOUT2 = sha.XOR((char) H[3], (char) byteOUT2,cipherKeyString);
         int nibble4 = (byteOUT2 << 4) & 0xf0;
         int nibble5 = (byteOUT2 >>> 4) & 0x0f;

         byte byteOUT3 = sha.XOR((char) sha.myKey[BB3], (char) sha.myKey[BB7],cipherKeyString);
         byteOUT3 = sha.XOR((char) H[4], (char) byteOUT3,cipherKeyString);
         int nibble6 = (byteOUT3 << 4) & 0xf0;
         int nibble7 = (byteOUT3 >>> 4) & 0x0f;

         // Make new keyCksum
         int num = (nibble7 << 12) | (nibble6 << 8) | (nibble5 << 4) | (nibble4 << 0);
         keyCksum = (int) (num % (Z_SIZE - 2));
         if (keyCksum > (Z_SIZE - 2) || keyCksum < 0) {
            keyCksum = (int) (num % (Z_SIZE / 2));
         }

         byteOUT0 = (byte) ((nibble1 | nibble0));
         byteOUT1 = (byte) ((nibble3 | nibble2));
         byteOUT2 = (byte) ((nibble5 | nibble4));
         byteOUT3 = (byte) ((nibble7 | nibble6));

         Scacmd.write((byte) byteOUT0);
         Scacmd.write((byte) byteOUT1);
         Scacmd.write((byte) byteOUT2);
         Scacmd.write((byte) byteOUT3);

         // Create new hash for file data.
         sha.sha256(cipherKeyString + Integer.toString(keyCksum));

         // Write the four read in data bytes to ciphertext file.
         byteOUT = sha.XOR((char) rx.bytesIN[0], (char) sha.myKey[0],cipherKeyString);
         Scacmd.write((byte) byteOUT);

         byteOUT = sha.XOR((char) rx.bytesIN[1], (char) sha.myKey[1],cipherKeyString);
         Scacmd.write((byte) byteOUT);

         byteOUT = sha.XOR((char) rx.bytesIN[2], (char) sha.myKey[2],cipherKeyString);
         Scacmd.write((byte) byteOUT);

         byteOUT = sha.XOR((char) rx.bytesIN[3], (char) sha.myKey[3],cipherKeyString);
         Scacmd.write((byte) byteOUT);

      } // End ENCRYPT only logic.
      Scacmd.flush();

      // Get new Bb from array S
      int Bb = keyCksum;
      Bb = AS.S[Bb];
      if (Bb >= Z_SIZE - 2) {
         Bb = AS.S[keyCksum];
      }

      // Starting index for AZ.Z[z]
      int s = 0;
      k = AZ.Z[Bb] % (Bb) * (keyCksum);
      if (k <= 0) {
         k = Bb;
      }

      while (k >= Z_SIZE - 2) {
         k = k - Bb;
         if (k <= 0) {
            k = Bb; // Infinite loop break.
         }
      }

      // Set default values for z if overflow.
      if (k >= Z_SIZE - 2) {
         k = Bb;
      }
      int Ak = AZ.Z[k] % (Bb);

      if (Ak >= Z_SIZE - 2) {
         Ak = k;
      }

      int Bk = AZ.Z[Ak] % (Bb);
      if (Ak >= Z_SIZE - 2) {
         Bk = Ak;
      }

      int Ck = AZ.Z[Bk] % (Bb);
      if (Ak >= Z_SIZE - 2) {
         Ck = Bk;
      }
      z = Bb;

      // Sets the value for sha.COUNT
      sha.getBlockCount(cipherKeyString);

      // Initialize key index r
      r = DEC ? 0 : (ENC ? 4 : r);

      // Decrypt the first four bytes.
      if (DEC) {
         for (i = 0; i < 4; i++) {
            Scacmd.write((byte) sha.XOR((char) Scacmd.readByte(), (char) sha.myKey[r++],cipherKeyString));
         }
      }
      Scacmd.flush();

      i = 1;
      j = 1;
      p = 0;

      // Encrypt Logic
      if (ENC) {
         while (!Scacmd.isEmpty()) {
            rx.bytesIN[i++] = Scacmd.readByte();
            if (i == BLOCK_SIZE) {
               rx.fillRubix(BLOCK_SIZE);
               rx.blockCipher_E(cipherKeyString); // Block encrypt.
               rx.fillBytesOUT();
               for (j = 1; j < BLOCK_SIZE; j++) {
                  byteOUT = sha.XOR((char) rx.bytesOUT[j], (char) sha.myKey[r++],cipherKeyString);
                  Scacmd.write(byteOUT);
                  if (r == KEY_DIGEST) {
                     sha.sha256Short(String.valueOf(AZ.Z[k]));    // get the sha256 digest.
                     sha.myKey[p] = sha.XOR((char) sha.shrtKey[p], (char) AZ.Z[k++],cipherKeyString); // change the key every chunk of bytes.
                     r = 0;
                     if (k >= Z_SIZE - 1) {
                        sha.myKey[p] = sha.myKeyS[p]; // reset back to orginal.
                        if (p++ >= KEY_DIGEST - 1) {
                           p = 0;
                        }
                        k = AS.S[z]; // get a new starting index for AZ.Z[z]
                        if (z++ >= S_SIZE - 1) {
                           z = 0;
                        }
                     }
                  }
               }
               i = 1;
               Scacmd.flush();
            }
            if (Scacmd.isEmpty()) {
               for (j = 1; j < i; j++) {
                  byteOUT = sha.XOR((char) rx.bytesIN[j], (char) sha.myKey[r++],cipherKeyString);
                  Scacmd.write(byteOUT);
                  if (r == KEY_DIGEST) {
                     sha.sha256Short(String.valueOf(AZ.Z[k]));    // get the sha256 digest.
                     sha.myKey[p] = sha.XOR((char) sha.shrtKey[p], (char) AZ.Z[k++],cipherKeyString); // change the key every chunk of bytes.
                     r = 0;
                     if (k >= Z_SIZE - 1) {
                        sha.myKey[p] = sha.myKeyS[p]; // reset back to orginal.
                        if (p++ >= KEY_DIGEST - 1) {
                           p = 0;
                        }
                        k = AS.S[z]; // get a new starting index for AZ.Z[z]
                        if (z++ >= S_SIZE - 1) {
                           z = 0;
                        }
                     }
                  }
               }
            }
         }
      }
      Scacmd.flush();

      // Decrypt logic.
      if (DEC) {
         while (!Scacmd.isEmpty()) {
            byteIN = Scacmd.readByte();
            rx.bytesIN[i] = sha.XOR((char) byteIN, (char) sha.myKey[r++],cipherKeyString);
            if (r == KEY_DIGEST) {
               sha.sha256Short(String.valueOf(AZ.Z[k]));    // get the sha256 digest.
               sha.myKey[p] = sha.XOR((char) sha.shrtKey[p], (char) AZ.Z[k++],cipherKeyString); // change the key every chunk of bytes.
               r = 0;
               if (k >= Z_SIZE - 1) {
                  sha.myKey[p] = sha.myKeyS[p]; // reset back to orginal.
                  if (p++ >= KEY_DIGEST - 1) {
                     p = 0;
                  }
                  k = AS.S[z]; // get a new starting index for AZ.Z[z]
                  if (z++ >= S_SIZE - 1) {
                     z = 0;
                  }
               }
            }
            i++;
            if (i == BLOCK_SIZE) {
               rx.fillRubix(BLOCK_SIZE);
               rx.blockCipher_D(cipherKeyString);
               rx.fillBytesOUT();
               for (j = 1; j < BLOCK_SIZE; j++) {
                  Scacmd.write(rx.bytesOUT[j]);
               }
               i = 1;
               Scacmd.flush();
            }
            if (Scacmd.isEmpty()) {
               for (j = 1; j < i; j++) {
                  Scacmd.write(rx.bytesIN[j]);
               }
            }
         }
      } // if DEC
      Scacmd.flush();

   } // End Main
} // End Scacmd class
