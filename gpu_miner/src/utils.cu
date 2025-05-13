#include <stdio.h>
#include <stdint.h>
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

// CUDA sprintf alternative for nonce finding. Converts integer to its string representation. Returns string's length.
__device__ int intToString(uint64_t num, char* out) {
    if (num == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 2;
    }

    int i = 0;
    while (num != 0) {
        int digit = num % 10;
        num /= 10;
        out[i++] = '0' + digit;
    }

    // Reverse the string
    for (int j = 0; j < i / 2; j++) {
        char temp = out[j];
        out[j] = out[i - j - 1];
        out[i - j - 1] = temp;
    }
    out[i] = '\0';
    return i;
}

// CUDA strlen implementation.
__host__ __device__ size_t d_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// CUDA strcpy implementation.
__device__ void d_strcpy(char *dest, const char *src){
    int i = 0;
    while ((dest[i] = src[i]) != '\0') {
        i++;
    }
}

// CUDA strcat implementation.
__device__ void d_strcat(char *dest, const char *src){
    while (*dest != '\0') {
        dest++;
    }
    while (*src != '\0') {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
}

// Compute SHA256 and convert to hex
__host__ __device__ void apply_sha256(const BYTE *input, BYTE *output) {
    size_t input_length = d_strlen((const char *)input);
    SHA256_CTX ctx;
    BYTE buf[SHA256_BLOCK_SIZE];
    const char hex_chars[] = "0123456789abcdef";

    sha256_init(&ctx);
    sha256_update(&ctx, input, input_length);
    sha256_final(&ctx, buf);

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        output[i * 2]     = hex_chars[(buf[i] >> 4) & 0x0F];  // High nibble
        output[i * 2 + 1] = hex_chars[buf[i] & 0x0F];         // Low nibble
    }
    output[SHA256_BLOCK_SIZE * 2] = '\0'; // Null-terminate
}

// Compare two hashes
__host__ __device__ int compare_hashes(BYTE* hash1, BYTE* hash2) {
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        if (hash1[i] < hash2[i]) {
            return -1; // hash1 is lower
        } else if (hash1[i] > hash2[i]) {
            return 1; // hash2 is lower
        }
    }
    return 0; // hashes are equal
}

// Kernel pentru a calcula SHA-256 pentru fiecare tranzactie
__global__ void kernel_hash_transactions(BYTE *transactions, BYTE *hashes, int transaction_size, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) {
        return;
    }
    apply_sha256(transactions + idx * transaction_size, hashes + idx * SHA256_HASH_SIZE);
}

// Functie pentru a construi radacina Merkle
void construct_merkle_root(int transaction_size, BYTE *transactions, int max_transactions_in_a_block, int n, BYTE merkle_root[SHA256_HASH_SIZE]) {
    BYTE *device_transactions, *device_hashes;

    // Alocam memorie pentru hash-uri pe gazda
    BYTE *hashes = (BYTE *)malloc(max_transactions_in_a_block * SHA256_HASH_SIZE);

    // Alocam memorie pentru tranzactii si hash-uri pe GPU
    cudaMalloc(&device_transactions, n * transaction_size);
    cudaMalloc(&device_hashes, n * SHA256_HASH_SIZE);
    
    // Copiem tranzactiile pe GPU
    cudaMemcpy(device_transactions, transactions, n * transaction_size, cudaMemcpyHostToDevice);

    // 1) Calculam hash-urile pentru fiecare tranzactie
    int threads_per_block = 256;
    int blocks = (n + threads_per_block - 1) / threads_per_block;
    kernel_hash_transactions<<<blocks, threads_per_block>>>(device_transactions, device_hashes, transaction_size, n);
    cudaDeviceSynchronize();

    // Copiem inapoi hash-urile de pe GPU pe CPU si eliberam memoria GPU
    cudaMemcpy(hashes, device_hashes, n * SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    cudaFree(device_transactions);
    cudaFree(device_hashes);

    // 2) Reducem hash-urile pentru a obtine radacina Merkle
    while (n > 1) {
        int nr = 0;
        // Pentru fiecare pereche de hash-uri, le combinam si calculam hash-ul rezultat (sau duplicam ultimul hash daca n e impar)
        for (int i = 0; i < n; i += 2) {
            BYTE combined[SHA256_HASH_SIZE * 2];  // Buffer pentru a combina doua hash-uri
            if (i + 1 < n) {
                memcpy(combined, &hashes[i * SHA256_HASH_SIZE], SHA256_HASH_SIZE);  // Copiem primul hash
                memcpy(combined + SHA256_HASH_SIZE, &hashes[(i + 1) * SHA256_HASH_SIZE], SHA256_HASH_SIZE);  // Copiem al doilea hash
            } else {
                memcpy(combined, &hashes[i * SHA256_HASH_SIZE], SHA256_HASH_SIZE);  // Copiem ultimul hash
                memcpy(combined + SHA256_HASH_SIZE, &hashes[i * SHA256_HASH_SIZE], SHA256_HASH_SIZE);  // Duplicam ultimul hash
            }
            // Aplicam SHA256 pe hash-urile combinate
            apply_sha256(combined, &hashes[nr * SHA256_HASH_SIZE]);
            nr++;
        }
        n = nr;  // Actualizam numarul de hash-uri
    }

    // 3) Copiem radacina Merkle in merkle_root
    memcpy(merkle_root, hashes, SHA256_HASH_SIZE);
    free(hashes);
}

// Kernel pentru a gasi nonce-ul valid
__global__ void find_valid_nonce(BYTE *difficulty, BYTE *block_content, size_t content_length, uint32_t max_nonce, int *found_flag, uint32_t *found_nonce, BYTE *resultingHash) {
    uint32_t nonce = blockIdx.x * blockDim.x + threadIdx.x;

    if (nonce > max_nonce || *found_flag) {
        return;
    }

    // Cream un bloc local pentru a concatena continutul blocului si nonce-ul
    char local_block[BLOCK_SIZE];
    char nonce_str[NONCE_SIZE];
    BYTE computed_hash[SHA256_HASH_SIZE];

    // Copiem continutul blocului in local_block
    for (int i = 0; i < content_length; ++i) {
        local_block[i] = block_content[i];
    }
    local_block[content_length] = '\0';

    // Convertim nonce-ul in string si il adaugam la local_block
    int nonce_len = intToString(nonce, nonce_str);
    for (int i = 0; i < nonce_len; ++i) {
        local_block[content_length + i] = nonce_str[i];
    }
    local_block[content_length + nonce_len] = '\0';

    // Aplicam SHA256 pe local_block
    apply_sha256((BYTE *)local_block, computed_hash);

    // Verificam daca hash-ul este mai mic decat dificultatea
    if (compare_hashes(computed_hash, difficulty) <= 0) {
        // Daca e primul nonce gasit, il salvam si setam flag-ul
        int old_value = atomicExch(found_flag, 1);
        if (old_value == 0) {
            *found_nonce = nonce;  // Retinem valoarea nonce-ului gasit
            // Copiem hash-ul gasit in resultingHash
            for (int i = 0; i < SHA256_HASH_SIZE; ++i) {
                resultingHash[i] = computed_hash[i];
            }
        }
    }
}

// Functie pentru a gasi nonce-ul valid
int find_nonce(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, size_t current_length, BYTE *block_hash, uint32_t *valid_nonce) {
    BYTE *device_diffculty, *device_block_content, *device_found_hash;
    int *device_found_flag;
    uint32_t *device_valid_nonce;
    int found_flag = 0;

    // Alocam memorie pe GPU
    cudaMalloc(&device_diffculty, SHA256_HASH_SIZE);
    cudaMalloc(&device_block_content, BLOCK_SIZE);
    cudaMalloc(&device_found_flag, sizeof(int));
    cudaMalloc(&device_valid_nonce, sizeof(uint32_t));
    cudaMalloc(&device_found_hash, SHA256_HASH_SIZE);

    // Copiem datele de pe gazda pe GPU
    cudaMemcpy(device_diffculty, difficulty, SHA256_HASH_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(device_block_content, block_content, current_length, cudaMemcpyHostToDevice);
    cudaMemcpy(device_found_flag, &found_flag, sizeof(int), cudaMemcpyHostToDevice);

    // Calculeaza cate blocuri si threaduri lansam
    size_t threads_per_block = 256;
    size_t launch_blocks = (static_cast<size_t>(max_nonce) + threads_per_block) / threads_per_block;

    // Calculam nonce-ul valid
    find_valid_nonce<<<launch_blocks, threads_per_block>>>(device_diffculty, device_block_content, current_length, max_nonce, device_found_flag, (uint32_t*)device_valid_nonce, device_found_hash);
    cudaDeviceSynchronize();

    // Copiem rezultatele inapoi pe gazda
    cudaMemcpy(&found_flag, device_found_flag, sizeof(int), cudaMemcpyDeviceToHost);

    // Daca am gasit un nonce valid, copiem nonce-ul si hash-ul gasit inapoi pe gazda
    if (found_flag) {
        cudaMemcpy(valid_nonce, device_valid_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(block_hash, device_found_hash, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    }

    // Eliberam memoria GPU
    cudaFree(device_diffculty);
    cudaFree(device_block_content);
    cudaFree(device_found_flag);
    cudaFree(device_valid_nonce);
    cudaFree(device_found_hash);

    // Returnam 0 daca am gasit un nonce valid, altfel 1
    if (found_flag) {
        return 0;
    } else {
        return 1;
    }
}

__global__ void dummy_kernel() {}

// Warm-up function
void warm_up_gpu() {
    BYTE *dummy_data;
    cudaMalloc((void **)&dummy_data, 256);
    dummy_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaFree(dummy_data);
}
