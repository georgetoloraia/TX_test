#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>


#define NUM_KEYS 100000
#define KEY_LENGTH 64 // 32 hex characters = 128 bits

// Function to generate a random hex character (0-9, a-f)
char get_random_hex_char() {
    int r = rand() % 16;
    if (r < 10) return '0' + r;
    return 'a' + (r - 10);
}

int main() {
    // Seed the random number generator
    srand(time(NULL));

    // Open file for writing
    FILE *file = fopen("known_keys2.txt", "w");
    if (file == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    // Generate 50,000 keys
    for (int i = 0; i < NUM_KEYS; i++) {
        // Generate a 32-character hex key
        char key[KEY_LENGTH + 1]; // +1 for null terminator
        for (int j = 0; j < KEY_LENGTH; j++) {
            key[j] = get_random_hex_char();
        }
        key[KEY_LENGTH] = '\0'; // Null-terminate the string

        // Create a 64-character zero-padded key
        char padded_key[65]; // 64 chars + null terminator
        int padding = 64 - KEY_LENGTH; // Number of zeros to prepend
        memset(padded_key, '0', padding); // Fill start with zeros
        strcpy(padded_key + padding, key); // Append the generated key
        padded_key[64] = '\0'; // Null-terminate the padded key

        // Write padded key to file with a newline
        fprintf(file, "%s\n", padded_key);
    }

    // Close the file
    fclose(file);
    printf("Generated %d private keys and saved to known_keys2.txt\n", NUM_KEYS);
    return 0;
}