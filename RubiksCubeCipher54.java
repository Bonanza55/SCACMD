import java.security.MessageDigest;
import java.lang.*;

public class RubiksCubeCipher54 {

    // Declare the cube faces (3x3) using byte arrays
    public static byte[][] TOP = new byte[4][4];
    public static byte[][] BOT = new byte[4][4];
    public static byte[][] FNT = new byte[4][4];
    public static byte[][] LFT = new byte[4][4];
    public static byte[][] BAK = new byte[4][4];
    public static byte[][] RIT = new byte[4][4];

    // Arrays to simulate input and output data
    public static byte[] bytesIN = new byte[100]; // Data input array
    public static byte[] bytesOUT = new byte[100]; // Data output array

    public static void fillRubix(int BLOCK_SIZE) {
        int index = 1; // Start at index 1, not 0
        // Ensure we don't exceed the BLOCK_SIZE
        for (int face = 0; face < 6; face++) {
            for (int i = 1; i <= 3; i++) {
                for (int j = 1; j <= 3; j++) {
                    if (index <= BLOCK_SIZE) {
                        // Fill each face based on the face index
                        switch (face) {
                            case 0: TOP[i][j] = bytesIN[index++]; break;  // Top face
                            case 1: BOT[i][j] = bytesIN[index++]; break;  // Bottom face
                            case 2: FNT[i][j] = bytesIN[index++]; break; // Front face
                            case 3: LFT[i][j] = bytesIN[index++]; break; // Left face
                            case 4: BAK[i][j] = bytesIN[index++]; break; // Back face
                            case 5: RIT[i][j] = bytesIN[index++]; break; // Right face
                        }
                    }
                }
            }
        }
    }

    // Unload the current cube faces into the bytesOUT array
    public static void fillBytesOUT() {
        int index = 1; // Start at index 1, not 0
        bytesOUT[index++] = TOP[1][1];
        bytesOUT[index++] = TOP[1][2];
        bytesOUT[index++] = TOP[1][3];
        bytesOUT[index++] = TOP[2][1];
        bytesOUT[index++] = TOP[2][2];
        bytesOUT[index++] = TOP[2][3];
        bytesOUT[index++] = TOP[3][1];
        bytesOUT[index++] = TOP[3][2];
        bytesOUT[index++] = TOP[3][3];

        bytesOUT[index++] = BOT[1][1];
        bytesOUT[index++] = BOT[1][2];
        bytesOUT[index++] = BOT[1][3];
        bytesOUT[index++] = BOT[2][1];
        bytesOUT[index++] = BOT[2][2];
        bytesOUT[index++] = BOT[2][3];
        bytesOUT[index++] = BOT[3][1];
        bytesOUT[index++] = BOT[3][2];
        bytesOUT[index++] = BOT[3][3];

        bytesOUT[index++] = FNT[1][1];
        bytesOUT[index++] = FNT[1][2];
        bytesOUT[index++] = FNT[1][3];
        bytesOUT[index++] = FNT[2][1];
        bytesOUT[index++] = FNT[2][2];
        bytesOUT[index++] = FNT[2][3];
        bytesOUT[index++] = FNT[3][1];
        bytesOUT[index++] = FNT[3][2];
        bytesOUT[index++] = FNT[3][3];

        bytesOUT[index++] = LFT[1][1];
        bytesOUT[index++] = LFT[1][2];
        bytesOUT[index++] = LFT[1][3];
        bytesOUT[index++] = LFT[2][1];
        bytesOUT[index++] = LFT[2][2];
        bytesOUT[index++] = LFT[2][3];
        bytesOUT[index++] = LFT[3][1];
        bytesOUT[index++] = LFT[3][2];
        bytesOUT[index++] = LFT[3][3];

        bytesOUT[index++] = BAK[1][1];
        bytesOUT[index++] = BAK[1][2];
        bytesOUT[index++] = BAK[1][3];
        bytesOUT[index++] = BAK[2][1];
        bytesOUT[index++] = BAK[2][2];
        bytesOUT[index++] = BAK[2][3];
        bytesOUT[index++] = BAK[3][1];
        bytesOUT[index++] = BAK[3][2];
        bytesOUT[index++] = BAK[3][3];

        bytesOUT[index++] = RIT[1][1];
        bytesOUT[index++] = RIT[1][2];
        bytesOUT[index++] = RIT[1][3];
        bytesOUT[index++] = RIT[2][1];
        bytesOUT[index++] = RIT[2][2];
        bytesOUT[index++] = RIT[2][3];
        bytesOUT[index++] = RIT[3][1];
        bytesOUT[index++] = RIT[3][2];
        bytesOUT[index++] = RIT[3][3];
    }

    // Method to generate a hash sequence from the passKey
    public static int[] generateHashSequence(String passKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = passKey.getBytes();
            byte[] hash = new byte[0];
            
            // Concatenate the hashes multiple times to create a sequence that matches the passKey length
            for (int i = 0; i < keyBytes.length; i++) {
                digest.update(keyBytes[i]);
                byte[] currentHash = digest.digest();
                byte[] tempHash = new byte[hash.length + currentHash.length];
                
                // Combine the previous hash with the current hash
                System.arraycopy(hash, 0, tempHash, 0, hash.length);
                System.arraycopy(currentHash, 0, tempHash, hash.length, currentHash.length);
                
                hash = tempHash;
            }

            int[] sequence = new int[hash.length];
            
            // Convert the byte sequence into an integer sequence for scramble steps
            for (int i = 0; i < hash.length; i++) {
                sequence[i] = (hash[i] & 0xFF) % 6; // Map to [0, 5] for 3x3 cube rotations/swaps
            }

            return sequence;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    // Method to encrypt (scramble) the cube based on the passKey
    public static void blockCipher_E(String passKey) {
        int[] hashSequence = generateHashSequence(passKey);

        for (int i = 0; i < hashSequence.length; i++) {
            // Perform a scramble operation based on the sequence
            int step = hashSequence[i];
            switch (step) {
                case 0: rotateTop(); break;
                case 1: rotateBot(); break;
                case 2: rotateLeft(); break;
                case 3: rotateRight(); break;
                case 4: rotateFront(); break;
                case 5: rotateBack(); break;
            }
        }
    }

    // IMPROVED: Method to rotate top face (3x3) with edge swapping
    public static void rotateTop() {
        // Rotate the top face itself clockwise
        byte temp = TOP[1][1];
        TOP[1][1] = TOP[3][1];
        TOP[3][1] = TOP[3][3];
        TOP[3][3] = TOP[1][3];
        TOP[1][3] = temp;
        
        temp = TOP[1][2];
        TOP[1][2] = TOP[2][1];
        TOP[2][1] = TOP[3][2];
        TOP[3][2] = TOP[2][3];
        TOP[2][3] = temp;
        
        // Rotate the edges: Front top row → Left top row → Back top row → Right top row → Front
        byte temp1 = FNT[1][1];
        byte temp2 = FNT[1][2];
        byte temp3 = FNT[1][3];
        
        FNT[1][1] = RIT[1][1];
        FNT[1][2] = RIT[1][2];
        FNT[1][3] = RIT[1][3];
        
        RIT[1][1] = BAK[1][1];
        RIT[1][2] = BAK[1][2];
        RIT[1][3] = BAK[1][3];
        
        BAK[1][1] = LFT[1][1];
        BAK[1][2] = LFT[1][2];
        BAK[1][3] = LFT[1][3];
        
        LFT[1][1] = temp1;
        LFT[1][2] = temp2;
        LFT[1][3] = temp3;
    }

    // IMPROVED: Method to rotate bottom face (3x3) with edge swapping
    public static void rotateBot() {
        // Rotate the bottom face itself clockwise
        byte temp = BOT[1][1];
        BOT[1][1] = BOT[3][1];
        BOT[3][1] = BOT[3][3];
        BOT[3][3] = BOT[1][3];
        BOT[1][3] = temp;
        
        temp = BOT[1][2];
        BOT[1][2] = BOT[2][1];
        BOT[2][1] = BOT[3][2];
        BOT[3][2] = BOT[2][3];
        BOT[2][3] = temp;
        
        // Rotate the edges: Front bottom row → Right bottom row → Back bottom row → Left bottom row → Front
        byte temp1 = FNT[3][1];
        byte temp2 = FNT[3][2];
        byte temp3 = FNT[3][3];
        
        FNT[3][1] = LFT[3][1];
        FNT[3][2] = LFT[3][2];
        FNT[3][3] = LFT[3][3];
        
        LFT[3][1] = BAK[3][1];
        LFT[3][2] = BAK[3][2];
        LFT[3][3] = BAK[3][3];
        
        BAK[3][1] = RIT[3][1];
        BAK[3][2] = RIT[3][2];
        BAK[3][3] = RIT[3][3];
        
        RIT[3][1] = temp1;
        RIT[3][2] = temp2;
        RIT[3][3] = temp3;
    }

    // IMPROVED: Method to rotate left face (3x3) with edge swapping
    public static void rotateLeft() {
        // Rotate left face itself clockwise
        byte temp = LFT[1][1];
        LFT[1][1] = LFT[3][1];
        LFT[3][1] = LFT[3][3];
        LFT[3][3] = LFT[1][3];
        LFT[1][3] = temp;
        
        temp = LFT[1][2];
        LFT[1][2] = LFT[2][1];
        LFT[2][1] = LFT[3][2];
        LFT[3][2] = LFT[2][3];
        LFT[2][3] = temp;
        
        // Rotate edges: TOP left column → FRONT left column → BOT left column → BACK right column (reversed) → TOP
        byte temp1 = TOP[1][1];
        byte temp2 = TOP[2][1];
        byte temp3 = TOP[3][1];
        
        TOP[1][1] = BAK[3][3];
        TOP[2][1] = BAK[2][3];
        TOP[3][1] = BAK[1][3];
        
        BAK[3][3] = BOT[1][1];
        BAK[2][3] = BOT[2][1];
        BAK[1][3] = BOT[3][1];
        
        BOT[1][1] = FNT[1][1];
        BOT[2][1] = FNT[2][1];
        BOT[3][1] = FNT[3][1];
        
        FNT[1][1] = temp1;
        FNT[2][1] = temp2;
        FNT[3][1] = temp3;
    }

    // IMPROVED: Method to rotate right face (3x3) with edge swapping
    public static void rotateRight() {
        // Rotate right face itself clockwise
        byte temp = RIT[1][1];
        RIT[1][1] = RIT[3][1];
        RIT[3][1] = RIT[3][3];
        RIT[3][3] = RIT[1][3];
        RIT[1][3] = temp;
        
        temp = RIT[1][2];
        RIT[1][2] = RIT[2][1];
        RIT[2][1] = RIT[3][2];
        RIT[3][2] = RIT[2][3];
        RIT[2][3] = temp;
        
        // Rotate edges: TOP right column → BACK left column (reversed) → BOT right column → FRONT right column → TOP
        byte temp1 = TOP[1][3];
        byte temp2 = TOP[2][3];
        byte temp3 = TOP[3][3];
        
        TOP[1][3] = FNT[1][3];
        TOP[2][3] = FNT[2][3];
        TOP[3][3] = FNT[3][3];
        
        FNT[1][3] = BOT[1][3];
        FNT[2][3] = BOT[2][3];
        FNT[3][3] = BOT[3][3];
        
        BOT[1][3] = BAK[3][1];
        BOT[2][3] = BAK[2][1];
        BOT[3][3] = BAK[1][1];
        
        BAK[3][1] = temp1;
        BAK[2][1] = temp2;
        BAK[1][1] = temp3;
    }

    // IMPROVED: Method to rotate front face (3x3) with edge swapping
    public static void rotateFront() {
        // Rotate front face itself clockwise
        byte temp = FNT[1][1];
        FNT[1][1] = FNT[3][1];
        FNT[3][1] = FNT[3][3];
        FNT[3][3] = FNT[1][3];
        FNT[1][3] = temp;
        
        temp = FNT[1][2];
        FNT[1][2] = FNT[2][1];
        FNT[2][1] = FNT[3][2];
        FNT[3][2] = FNT[2][3];
        FNT[2][3] = temp;
        
        // Rotate edges: TOP bottom row → RIGHT left column → BOT top row (reversed) → LEFT right column → TOP
        byte temp1 = TOP[3][1];
        byte temp2 = TOP[3][2];
        byte temp3 = TOP[3][3];
        
        TOP[3][1] = LFT[3][3];
        TOP[3][2] = LFT[2][3];
        TOP[3][3] = LFT[1][3];
        
        LFT[1][3] = BOT[1][1];
        LFT[2][3] = BOT[1][2];
        LFT[3][3] = BOT[1][3];
        
        BOT[1][1] = RIT[3][1];
        BOT[1][2] = RIT[2][1];
        BOT[1][3] = RIT[1][1];
        
        RIT[1][1] = temp1;
        RIT[2][1] = temp2;
        RIT[3][1] = temp3;
    }

    // IMPROVED: Method to rotate back face (3x3) with edge swapping
    public static void rotateBack() {
        // Rotate back face itself clockwise
        byte temp = BAK[1][1];
        BAK[1][1] = BAK[3][1];
        BAK[3][1] = BAK[3][3];
        BAK[3][3] = BAK[1][3];
        BAK[1][3] = temp;
        
        temp = BAK[1][2];
        BAK[1][2] = BAK[2][1];
        BAK[2][1] = BAK[3][2];
        BAK[3][2] = BAK[2][3];
        BAK[2][3] = temp;
        
        // Rotate edges: TOP top row (reversed) → LEFT left column → BOT bottom row (reversed) → RIGHT right column → TOP
        byte temp1 = TOP[1][1];
        byte temp2 = TOP[1][2];
        byte temp3 = TOP[1][3];
        
        TOP[1][1] = RIT[1][3];
        TOP[1][2] = RIT[2][3];
        TOP[1][3] = RIT[3][3];
        
        RIT[1][3] = BOT[3][3];
        RIT[2][3] = BOT[3][2];
        RIT[3][3] = BOT[3][1];
        
        BOT[3][3] = LFT[3][1];
        BOT[3][2] = LFT[2][1];
        BOT[3][1] = LFT[1][1];
        
        LFT[1][1] = temp1;
        LFT[2][1] = temp2;
        LFT[3][1] = temp3;
    }

    // Method to decrypt (solve) the cube based on the passKey
    public static void blockCipher_D(String passKey) {
        int[] hashSequence = generateHashSequence(passKey);

        // Reverse the scrambling process (opposite order)
        for (int i = hashSequence.length - 1; i >= 0; i--) {
            int step = hashSequence[i];
            switch (step) {
                case 0: rotateTopInverse(); break;
                case 1: rotateBotInverse(); break;
                case 2: rotateLeftInverse(); break;
                case 3: rotateRightInverse(); break;
                case 4: rotateFrontInverse(); break;
                case 5: rotateBackInverse(); break;
            }
        }
    }

    // IMPROVED: Inverse rotation for top face with edge swapping
    public static void rotateTopInverse() {
        // Rotate the top face itself counter-clockwise
        byte temp = TOP[1][1];
        TOP[1][1] = TOP[1][3];
        TOP[1][3] = TOP[3][3];
        TOP[3][3] = TOP[3][1];
        TOP[3][1] = temp;
        
        temp = TOP[1][2];
        TOP[1][2] = TOP[2][3];
        TOP[2][3] = TOP[3][2];
        TOP[3][2] = TOP[2][1];
        TOP[2][1] = temp;
        
        // Rotate edges in reverse: Front top row → Right top row → Back top row → Left top row → Front
        byte temp1 = FNT[1][1];
        byte temp2 = FNT[1][2];
        byte temp3 = FNT[1][3];
        
        FNT[1][1] = LFT[1][1];
        FNT[1][2] = LFT[1][2];
        FNT[1][3] = LFT[1][3];
        
        LFT[1][1] = BAK[1][1];
        LFT[1][2] = BAK[1][2];
        LFT[1][3] = BAK[1][3];
        
        BAK[1][1] = RIT[1][1];
        BAK[1][2] = RIT[1][2];
        BAK[1][3] = RIT[1][3];
        
        RIT[1][1] = temp1;
        RIT[1][2] = temp2;
        RIT[1][3] = temp3;
    }

    // IMPROVED: Inverse rotation for bottom face with edge swapping
    public static void rotateBotInverse() {
        // Rotate the bottom face itself counter-clockwise
        byte temp = BOT[1][1];
        BOT[1][1] = BOT[1][3];
        BOT[1][3] = BOT[3][3];
        BOT[3][3] = BOT[3][1];
        BOT[3][1] = temp;
        
        temp = BOT[1][2];
        BOT[1][2] = BOT[2][3];
        BOT[2][3] = BOT[3][2];
        BOT[3][2] = BOT[2][1];
        BOT[2][1] = temp;
        
        // Rotate edges in reverse: Front bottom row → Left bottom row → Back bottom row → Right bottom row → Front
        byte temp1 = FNT[3][1];
        byte temp2 = FNT[3][2];
        byte temp3 = FNT[3][3];
        
        FNT[3][1] = RIT[3][1];
        FNT[3][2] = RIT[3][2];
        FNT[3][3] = RIT[3][3];
        
        RIT[3][1] = BAK[3][1];
        RIT[3][2] = BAK[3][2];
        RIT[3][3] = BAK[3][3];
        
        BAK[3][1] = LFT[3][1];
        BAK[3][2] = LFT[3][2];
        BAK[3][3] = LFT[3][3];
        
        LFT[3][1] = temp1;
        LFT[3][2] = temp2;
        LFT[3][3] = temp3;
    }

    // IMPROVED: Inverse rotation for left face with edge swapping
    public static void rotateLeftInverse() {
        // Rotate left face itself counter-clockwise
        byte temp = LFT[1][1];
        LFT[1][1] = LFT[1][3];
        LFT[1][3] = LFT[3][3];
        LFT[3][3] = LFT[3][1];
        LFT[3][1] = temp;
        
        temp = LFT[1][2];
        LFT[1][2] = LFT[2][3];
        LFT[2][3] = LFT[3][2];
        LFT[3][2] = LFT[2][1];
        LFT[2][1] = temp;
        
        // Rotate edges in reverse
        byte temp1 = TOP[1][1];
        byte temp2 = TOP[2][1];
        byte temp3 = TOP[3][1];
        
        TOP[1][1] = FNT[1][1];
        TOP[2][1] = FNT[2][1];
        TOP[3][1] = FNT[3][1];
        
        FNT[1][1] = BOT[1][1];
        FNT[2][1] = BOT[2][1];
        FNT[3][1] = BOT[3][1];
        
        BOT[1][1] = BAK[3][3];
        BOT[2][1] = BAK[2][3];
        BOT[3][1] = BAK[1][3];
        
        BAK[3][3] = temp1;
        BAK[2][3] = temp2;
        BAK[1][3] = temp3;
    }

    // IMPROVED: Inverse rotation for right face with edge swapping
    public static void rotateRightInverse() {
        // Rotate right face itself counter-clockwise
        byte temp = RIT[1][1];
        RIT[1][1] = RIT[1][3];
        RIT[1][3] = RIT[3][3];
        RIT[3][3] = RIT[3][1];
        RIT[3][1] = temp;
        
        temp = RIT[1][2];
        RIT[1][2] = RIT[2][3];
        RIT[2][3] = RIT[3][2];
        RIT[3][2] = RIT[2][1];
        RIT[2][1] = temp;
        
        // Rotate edges in reverse
        byte temp1 = TOP[1][3];
        byte temp2 = TOP[2][3];
        byte temp3 = TOP[3][3];
        
        TOP[1][3] = BAK[3][1];
        TOP[2][3] = BAK[2][1];
        TOP[3][3] = BAK[1][1];
        
        BAK[3][1] = BOT[1][3];
        BAK[2][1] = BOT[2][3];
        BAK[1][1] = BOT[3][3];
        
        BOT[1][3] = FNT[1][3];
        BOT[2][3] = FNT[2][3];
        BOT[3][3] = FNT[3][3];
        
        FNT[1][3] = temp1;
        FNT[2][3] = temp2;
        FNT[3][3] = temp3;
    }

    // IMPROVED: Inverse rotation for front face with edge swapping
    public static void rotateFrontInverse() {
        // Rotate front face itself counter-clockwise
        byte temp = FNT[1][1];
        FNT[1][1] = FNT[1][3];
        FNT[1][3] = FNT[3][3];
        FNT[3][3] = FNT[3][1];
        FNT[3][1] = temp;
        
        temp = FNT[1][2];
        FNT[1][2] = FNT[2][3];
        FNT[2][3] = FNT[3][2];
        FNT[3][2] = FNT[2][1];
        FNT[2][1] = temp;
        
        // Rotate edges in reverse
        byte temp1 = TOP[3][1];
        byte temp2 = TOP[3][2];
        byte temp3 = TOP[3][3];
        
        TOP[3][1] = RIT[1][1];
        TOP[3][2] = RIT[2][1];
        TOP[3][3] = RIT[3][1];
        
        RIT[1][1] = BOT[1][3];
        RIT[2][1] = BOT[1][2];
        RIT[3][1] = BOT[1][1];
        
        BOT[1][1] = LFT[1][3];
        BOT[1][2] = LFT[2][3];
        BOT[1][3] = LFT[3][3];
        
        LFT[1][3] = temp3;
        LFT[2][3] = temp2;
        LFT[3][3] = temp1;
    }

    // IMPROVED: Inverse rotation for back face with edge swapping
    public static void rotateBackInverse() {
        // Rotate back face itself counter-clockwise
        byte temp = BAK[1][1];
        BAK[1][1] = BAK[1][3];
        BAK[1][3] = BAK[3][3];
        BAK[3][3] = BAK[3][1];
        BAK[3][1] = temp;
        
        temp = BAK[1][2];
        BAK[1][2] = BAK[2][3];
        BAK[2][3] = BAK[3][2];
        BAK[3][2] = BAK[2][1];
        BAK[2][1] = temp;
        
        // Rotate edges in reverse
        byte temp1 = TOP[1][1];
        byte temp2 = TOP[1][2];
        byte temp3 = TOP[1][3];
        
        TOP[1][1] = LFT[1][1];
        TOP[1][2] = LFT[2][1];
        TOP[1][3] = LFT[3][1];
        
        LFT[1][1] = BOT[3][1];
        LFT[2][1] = BOT[3][2];
        LFT[3][1] = BOT[3][3];
        
        BOT[3][1] = RIT[3][3];
        BOT[3][2] = RIT[2][3];
        BOT[3][3] = RIT[1][3];
        
        RIT[1][3] = temp1;
        RIT[2][3] = temp2;
        RIT[3][3] = temp3;
    }
}
