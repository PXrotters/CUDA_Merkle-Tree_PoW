# Tema 2: CUDA - Merkle Tree & Proof-of-Work

**Nume:** Lemnaru Mihai-Daniel  
**Grupa:** 331CD  

---

## 📘 Descriere
Implementarea in CUDA a arborelui Merkle si a algoritmului de consens Proof-of-Work din cadrul Bitcoin.

## ⚙️ Organizare solutie
### Merkle Tree
1) Am hash-uit fiecare tranzactie individuala pe GPU cu ajutorul kernelului **`kernel_hash_transactions`**;
2) Am grupat hash-urile doua cate doua si am calculat hash-ul rezultat din concatenare pe CPU;
3) Am repetat procesul pana cand am ramas cu un singur hash, acesta reprezentand Merkle Root. 

### Proof-of-Work
1) Fiecare thread testeaza un nonce diferit, construieste string-ul bloc+nonce, aplica SHA-256 si compara cu difficulty.
2) Primul thread care gaseste solutia foloseste `atomicExch(found_flag,1)` pentru a salva nonce-ul si hash-ul in memorie.

Cazuri speciale: Numar impar de noduri in Merkle Tree => ultimul hash este duplicat.

## 🛠️ Implementare
- Am implementat toate cerintele: Merkle Tree si Proof-of-Work in CUDA.
- Kernel-uri:
  * **`kernel_hash_transactions`** -> Calculeaza SHA-256 pentru fiecare tranzactie
  * **`find_valid_nonce`** -> Gaseste primul nonce gasit
- Functii:
  * **`construct_merkle_root`** -> construieste merkle root-ul 
  * **`find_nonce`** -> gaseste nonce-ul valid
 - **Observatii:** As fi putut sa paralelizez si reducerea nivelurilor superioare din Merkle-Tree pe GPU, dar am pastrat aceasta secventa intr-o maniera seriala.

### 📚 Resurse utilizate
- Laboratoare :
  * Laboratorul 04 - Arhitecturi de tip GPGPU;
  * Laboratorul 05 - Arhitectura GPU NVIDIA CUDA
  * Laboratorul 06 - Advanced CUDA
- Documentatie :
   * CUDA C++ Programming Guide : https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html#atomicexch
   * CUDA C Programming Guide: https://www3.nd.edu/~zxu2/acms60212-40212/CUDA_C_Programming_Guide.pdf

### Observatii generale:
Tema a fost foarte bine explicata, pasii fiind clari si usor de urmarit, insa organizarea checker-ului au lasat de dorit si nu am putut sa ne dam seama de corectitudinea implementarii.

### 🔗 GitHub
Link repo: https://github.com/PXrotters/CUDA_Merkle-Tree_PoW
