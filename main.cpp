#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include <fstream>
#include <string>
#include <openssl/sha.h>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/applink.c>



using namespace std;

ifstream inputFile("name.txt");

void printArray(unsigned const char* const arr, unsigned const len, const char* const name)
{
    printf("\nThe content of the %s array is (hex): ", name);
    for (unsigned char i = 0; i < len; i++)
    {
        printf("%02x", arr[i]);
    }
}

void Ex1()
{

    FILE* fsrc = NULL;
    FILE* fdst = NULL;
    errno_t err;
    SHA256_CTX ctx;

    // Variables to store the SHA-256 digest and the final digital signature
    unsigned char finalDigest[SHA256_DIGEST_LENGTH];
    unsigned char* fileBuffer = NULL;

    // Initialize SHA-256 context
    SHA256_Init(&ctx);
    // Open the source file for reading in binary mode
    err = fopen_s(&fsrc, "name.txt", "rb"); // err 13 = denied permission (need to closeeee the file :)) )
    fseek(fsrc, 0, SEEK_END);
    int fileLen = ftell(fsrc);
    fseek(fsrc, 0, SEEK_SET);

    // Allocate buffer to store file content
    fileBuffer = (unsigned char*)malloc(fileLen);
    fread(fileBuffer, fileLen, 1, fsrc);
    unsigned char* tmpBuffer = fileBuffer;

    // Update SHA-256 context with file content
    while (fileLen > 0) {
        if (fileLen > SHA256_DIGEST_LENGTH) {
            SHA256_Update(&ctx, tmpBuffer, SHA256_DIGEST_LENGTH);
        }
        else {
            SHA256_Update(&ctx, tmpBuffer, fileLen);
        }
        fileLen -= SHA256_DIGEST_LENGTH;
        tmpBuffer += SHA256_DIGEST_LENGTH;
    }

    // Finalize SHA-256 and get the digest
    SHA256_Final(finalDigest, &ctx);

    // Print the SHA-256 digest
    printf("SHA(256) = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02X ", finalDigest[i]);
    printf("\n");

    fclose(fsrc);
}

int Ex2()
{
    //FILE* file;
    //char* buffer;
    //size_t fileSize;

    //// Open the file for reading
    //file = fopen("iv.txt", "r");

    //// Check if the file is opened successfully
    //if (file == NULL) {
    //    perror("Error opening the file");
    //    return 1; // Return an error code
    //}

    //// Determine the file size
    //fseek(file, 0, SEEK_END);
    //fileSize = ftell(file);
    //fseek(file, 0, SEEK_SET);

    //// Allocate memory for the buffer (plus one for the null terminator)
    //buffer = (char*)malloc(fileSize + 1);
    //if (buffer == NULL) {
    //    perror("Error allocating memory");
    //    fclose(file);
    //    return 1; // Return an error code
    //}

    //// Read the entire file into the buffer
    //fread(buffer, 1, fileSize, file);

    //// Null-terminate the buffer
    //buffer[fileSize] = '\0';

    //// Close the file
    //fclose(file);

    //// Now 'buffer' contains the file contents as a null-terminated string
    //// You can use 'fileSize' to determine the size of the string

    //// Your code to process the text goes here

    //cout << buffer << " ";


    //// Don't forget to free the allocated memory when done
    //free(buffer);
    FILE* f = fopen("name.txt", "r");
    size_t len = ftell(f);
    unsigned char* name = (unsigned char*)malloc(len);
	fread(name, len, 1, f);
	fclose(f);

    f = fopen("iv.txt", "r");
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char i = 0;
    unsigned int value;

    while (fscanf(f, " 0x%x,", &value) == 1 && i < AES_BLOCK_SIZE)
    {
        iv[i++] = (unsigned char)value;
    }

    fclose(f);
    
    f = fopen("aes.key", "rb");
    fseek(f, 0, SEEK_END);
    size_t key_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* key = (unsigned char*)malloc(key_len);
    fread(key, key_len, 1, f);
    fclose(f);

    AES_KEY aes_key;

    AES_set_encrypt_key(key, key_len * 8, &aes_key);

    size_t partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
    size_t ciphertext_blocks = len / AES_BLOCK_SIZE + partial_block;

    size_t padded_length = ciphertext_blocks * AES_BLOCK_SIZE;

    unsigned char* ciphertext = (unsigned char*)malloc(padded_length);

    printArray(iv, AES_BLOCK_SIZE, "iv");

    AES_cbc_encrypt(name, ciphertext, len, &aes_key, iv, AES_ENCRYPT);

    printArray(ciphertext, padded_length, "aes-256-cbc");

    f = fopen("enc_name.aes", "wb");
    fwrite(ciphertext, padded_length, 1, f);
    fclose(f);

    return 0;

}

int main()
{
    Ex1();
    Ex2();

	return 0;
}