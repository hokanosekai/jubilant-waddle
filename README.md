# Projet Yharnam - Malware PE Injector (Multi-stage)

## ✨ Description

Ce projet implémente un injecteur de fichiers PE 64 bits, capable d'infecter un exécutable en y ajoutant une nouvelle section contenant un code malveillant. Ce dernier affiche une `MessageBoxA` avant de redonner la main au point d'entrée original (OEP).

Il est à noter que ce projet suit une approche **multi-stages** :

1. Un **loader** (stage\_load.asm)
2. Le **payload principal** (MessageBox)
3. Un **stub de fin** (end\_stub.asm) qui saute vers l'OEP initial.

---

## ⚒️ Compilation

Prérequis :

* `cl.exe` (Microsoft Visual C Compiler)
* `ml64.exe` (MASM x64 Assembler)

Compilation via :

```sh
nmake all
```

---

## 🤖 Fichiers

| Nom              | Rôle                                                                 |
| ---------------- | -------------------------------------------------------------------- |
| `injector.c`     | Crée une section ".evil", modifie le PE Header, injecte le shellcode |
| `stage_load.asm` | Appelle le payload puis saute au code de restauration                |
| `end_stub.asm`   | Contient l'adresse de l'OEP et y saute                               |
| `Makefile`       | Script de build avec `cl.exe` et `ml64.exe`                          |

---

## ⚡ Fonctionnement interne

### ✍️ 1. Ajout d'une section `.evil`

```txt
+--------------------+
| .text              |
| .rdata             |
| ...                |
| .evil <--- ajout   |
+--------------------+
```

* Alignement sur 0x1000 pour la VA
* Alignement sur 0x200 pour le RAW

### ⚛️ 2. Modification de l'OEP

```c
OriginalEntryPoint = nt_headers->AddressOfEntryPoint;
nt_headers->AddressOfEntryPoint = .evil.VirtualAddress;
```

Le code malveillant sera ainsi exécuté avant toute chose.

### 🌀 3. Déroulement multi-stage

```txt
+--------------------+
| stage_load.asm     | --> call payload_main
|                    | --> call jump_to_oep
+--------------------+
| payload_main       | --> MessageBoxA()
+--------------------+
| end_stub.asm       | --> jmp OEP
+--------------------+
```

---

## 🎮 Comportement du Malware

* **Injection de fichier** : oui
* **Payload** : MessageBoxA("Infection Yharnam!", "Hello, Hunter")
* **Process cible** : Aucun process ciblé pour le moment (bonus non activé)
* **Chiffrement** : non (peut être ajouté en bonus)

---

## 🔑 Protection

Le payload est lisible en clair. Il est possible de le packer via simple XOR ou RC4 dans un fichier `payload_packed.asm` puis de l’ajouter au `stage_load.asm`.

---

## 🖋️ Exemple d'utilisation

```sh
PEInjector.exe target.exe payload.bin
```

Génère un `target.exe` infecté contenant la nouvelle section ".evil" et le shellcode.

---

## 📄 Auteurs

Voir `AUTHORS.txt`.
