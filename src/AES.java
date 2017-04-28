/*
Bradley White
CSCI 476: Bonus Lab
April 27, 2017
 */

public class AES {
    static char[][] plaintext = {{'a', 'e', 'i', 'm'}, {'b', 'f', 'j', 'n'}, {'c', 'g', 'k', 'o'}, {'d', 'h', 'l', 'p'}};
    static int[][] tran_matrix = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
    static int[][] stateArray = new int[plaintext.length][plaintext[0].length];
    static int[][] sbox = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

    public static void main(String[] args) {
        // Call helper to populate the state array
        convertCharToInt();
        //print2DStateArray();
        System.out.printf("The plaintext is:\n");
        printPlaintextOutput();
        System.out.printf("-----------------------------------------\n");

        // Iterate through all 10 rounds
        for (int round = 1; round < 11; round++) {
            // Special case to skip MixColumns in the last round
            if (round == 10) {
                subBytes();
                shiftRows();
                System.out.printf("After %d rounds (no MixColumn step), the state is:\n", round);
                printByteOutput();
                System.out.println();
            } else {
                // Call helper AES methods to encrypt the plaintext
                subBytes();
                shiftRows();
                //print2DStateArray();
                mixColumns();

                // Output the state after each round
                System.out.printf("After %d round(s), the state is\n", round);
                printByteOutput();
                //print2DStateArray();
                System.out.println();
            }
        }
    }

    // S-box substitution step
    public static void subBytes() {
        // Used to store the split bytes, each will have four bits
        int higher, lower;

        // Iterate through the block of bytes
        for (int row = 0; row < stateArray.length; row++) {
            for (int col = 0; col < stateArray[0].length; col++) {
                // Right shift the four left most bits and AND with 1111 bit mask
                higher = ((stateArray[row][col] >> 4) & 0xF);
                // Bit mask the four right most bits with 1111
                lower = (stateArray[row][col] & 0xF);
                // Substitute the byte in the byte block with the correct one from the sbox table
                stateArray[row][col] = sbox[higher][lower];
            }
        }
    }

    // Permutation step
    public static void shiftRows() {
        // Iterate through the block of bytes
        for (int row = 0; row < stateArray.length; row++) {
            // Use a working array to prevent overwritting bytes
            int[] workingArray = new int[stateArray[row].length];
            // Iterate through the row and put each byte in its correct position in the working array
            for (int col = 0; col < stateArray[0].length; col++) {
                workingArray[col] = stateArray[row][(row + col) % 4];
            }
            // Write the bytes to the state array in the correct order
            for (int i = 0; i < workingArray.length; i++) {
                stateArray[row][i] = workingArray[i];
            }
        }
    }

    // Matrix multiplication step
    public static void mixColumns() {
        // Hold the result for a single multiplication within the dot product
        int result;
        // Use a working array to avoid overwriting values in the state array
        int[][] workingArray = new int[stateArray.length][stateArray[0].length];

        // Iterate through the rows of the tran matrix
        for (int i = 0; i < tran_matrix.length; i++) {
            // Iterate through the columns of the state matrix
            for (int j = 0; j < tran_matrix[0].length; j++) {
                // Iterate through the values in each row/column to get the dot product
                for (int k = 0; k < tran_matrix[0].length; k++) {
                    // Reset to zero
                    result = 0;
                    // Special case when multiplying by three
                    if (tran_matrix[i][k] == 3) {
                        result ^= (2 * stateArray[k][j]) ^ stateArray[k][j];
                    } else {
                        result ^= (tran_matrix[i][k] * stateArray[k][j]);
                    }
                    // XOR with 283 (0001 0001 1011) to map to Galois Field
                    if (result > 255) {
                        result ^= 283;
                    }
                    // XOR with the accumulated sum for this position's dot product
                    workingArray[i][j] ^= result;
                }
            }
        }
        // Update the state
        stateArray = workingArray;
    }

    // Converts all the plaintext into the integer representation
    public static void convertCharToInt() {
        for (int row = 0; row < plaintext.length; row++) {
            for (int col = 0; col < plaintext[row].length; col++) {
                stateArray[row][col] = plaintext[row][col];
            }
        }
    }

    // Prints the current state row by row in hex
    public static void printByteOutput() {
        for (int row = 0; row < stateArray[0].length; row++) {
            for (int col = 0; col < stateArray.length; col++) {
                System.out.printf("%02X ", stateArray[row][col]);
            }
        }
        System.out.println();
    }

    // Prints the plaintext at the start of the program
    public static void printPlaintextOutput() {
        for (int col = 0; col < plaintext[0].length; col++) {
            for (int row = 0; row < plaintext.length; row++) {
                System.out.printf("%c ", plaintext[row][col]);
            }
        }
        System.out.println();
    }

    // These two methods were used for debugging purposes to print in an array format
    public static void print2DPlaintext() {
        for (int row = 0; row < plaintext.length; row++) {
            for (int col = 0; col < plaintext[row].length; col++) {
                System.out.printf("%c ", plaintext[row][col]);
            }
            System.out.println();
        }
    }

    public static void print2DStateArray() {
        for (int row = 0; row < stateArray.length; row++) {
            for (int col = 0; col < stateArray[row].length; col++) {
                System.out.printf("%02X ", stateArray[row][col]);
            }
            System.out.println();
        }
    }
}
