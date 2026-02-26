# Encripto - Bibliothèque de Chiffrement C Bas Niveau

[cite_start]**Version:** 1.0.0 [cite: 4]  
[cite_start]**Date:** 26 Février 2026 [cite: 4]  
[cite_start]**Statut:** En cours de définition [cite: 4]

## 1. Présentation du Projet
[cite_start]**Encripto** est une bibliothèque de cryptographie de bas niveau écrite entièrement en **C (Standard C11)**[cite: 7]. [cite_start]Elle est conçue spécifiquement pour l'environnement **Linux** afin de fournir des outils robustes, performants et sans aucune dépendance externe (malloc-free)[cite: 8, 53].

### Objectifs principaux :
* [cite_start]Implémenter les algorithmes les plus solides du secteur[cite: 10].
* [cite_start]Garantir des performances "proche du métal" avec un overhead nul[cite: 13].
* [cite_start]Fournir une API C claire (header-only possible) et un outil en ligne de commande (CLI)[cite: 11, 12].
* [cite_start]Assurer une portabilité totale sur les distributions Linux modernes (x86_64, ARM)[cite: 14].

---

## 2. Périmètre Technique

### Algorithmes Supportés
| Catégorie | Algorithme | Détails |
| :--- | :--- | :--- |
| **Chiffrement Symétrique** | **AES-256** | [cite_start]Modes CBC (Padding PKCS#7) et GCM (Authentifié)[cite: 35]. |
| **Chiffrement de Flux** | **ChaCha20-Poly1305** | [cite_start]Résistant aux attaques temporelles (RFC 8439)[cite: 39]. |
| **Asymétrique** | **RSA-4096** | [cite_start]Chiffrement OAEP et Signature PSS[cite: 37]. |
| **Hachage** | **SHA-256 / 512** | [cite_start]Conformes FIPS 180-4[cite: 40]. |
| **Authentification** | **HMAC** | [cite_start]Basé sur SHA-256 et SHA-512 (RFC 2104)[cite: 46]. |

---

## 3. Structure du Projet
[cite_start]Le projet est organisé de manière modulaire pour faciliter l'intégration[cite: 24]:
* [cite_start]`include/encripto.h` : Point d'entrée unique pour l'utilisateur[cite: 24].
* [cite_start]`src/` : Implémentations sources (AES, RSA, ChaCha20, SHA, etc.)[cite: 24].
* [cite_start]`cli/` : Code source de l'outil binaire `encripto`[cite: 24].
* [cite_start]`tests/` : Suite complète de tests unitaires et vecteurs de test NIST/RFC[cite: 24].

---

## 4. Exemple d'Utilisation (API C)
L'API est conçue pour être simple et sûre. [cite_start]Voici un exemple de hachage et de chiffrement[cite: 31, 32]:

```c
#include <encripto.h>

// Hachage SHA-256
uint8_t digest[32];
encripto_sha256(data, data_len, digest);

// Chiffrement AES-256-GCM
uint8_t key[32], iv[12], tag[16];
uint8_t ct[PLAINTEXT_LEN];
encripto_aes256_gcm_encrypt(key, iv, plaintext, len, ct, tag);
