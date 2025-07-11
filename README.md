# Projet Yharnam - Malware PE Injector

## Description

Ce projet implémente un injecteur de fichiers PE 64 bits, capable d'infecter un exécutable en y ajoutant une nouvelle section contenant un code malveillant. Ce dernier affiche une `MessageBoxA` avant de redonner la main au point d'entrée original (OEP).

---

## Compilation

Prérequis :

* `cl.exe` (Microsoft Visual C Compiler)
* `ml64.exe` (MASM x64 Assembler)
* `link.exe` (Microsoft Linker)

Compilation via :

```sh
nmake build
```

Il est également possible de lancer une injection sur un exécutable cible en utilisant la commande suivante :

```sh
nmake inject

# or

nmake inject TARGET=<chemin_vers_executable>
```

La target par défaut est `C:\Windows\System32\calc.exe`, mais vous pouvez spécifier un autre exécutable en utilisant l'option `TARGET`.

En lançant la commande `nmake all` vous pouvez compiler le projet et injecter le payload dans l'exécutable cible en une seule commande.

---

## Fichiers

| Nom              | Rôle                                                                 |
| ---------------- | -------------------------------------------------------------------- |
| `injector.c`     | Crée une section ".inj", modifie le PE Header, injecte le shellcode |
| `stage_load.asm` | Début du payload injecté, il permet d'appeler le payload en C puis de retourner à l'entrypoint orignal. |
| `payload.c`   | Contient le code malveillant (MessageBoxA)                             |
| `end_stub.asm`   | Fin du payload.                               |
| `makefile`       | Script de build avec `cl.exe` et `ml64.exe`                          |

---

## Fonctionnement interne

### 1. Ajout d'une section `.inj`

```txt
+--------------------+
| .text              |
| .rdata             |
| ...                |
| .inj <--- ajout    |
+--------------------+
```

* Alignement sur 0x1000 pour la VA
* Alignement sur 0x200 pour le RAW

### 2. Modification de l'OEP

Après l'ajout de la section `.inj`, le point d'entrée original (OEP) est modifié pour pointer vers le shellcode injecté.

```c
OriginalEntryPoint = nt_headers->AddressOfEntryPoint;
nt_headers->AddressOfEntryPoint = .inj.VirtualAddress;
```

Le code malveillant sera ainsi exécuté avant toute chose.

### 3. Patch de l'OEP

Afin de pouvoir revenir à l'OEP original après l'exécution du shellcode, un patch est effectué dans le payload lors de ca copie dans la section `.inj`.

```asm
vars:
    delta label QWORD
    dq 0        ; /!\ THIS IS A PLACEHOLDER /!\
                ; The actual delta will be patched by the injector
```

L'injecteur va donc chercher à modifier la variable `delta` contenue dans `start_code.asm` pour qu'elle corresponde à la différence entre l'adresse de l'OEP original et l'adresse du shellcode.

```c
*(LONGLONG *)(payload_copy + offset_delta) = oldEntryPointOffset;
```

Grace à ce delta, le shellcode pourra revenir à l'OEP original après son exécution.

```asm
_restore_state:
    add rsp, 40           ; free shadow space

    ; calculate the Original Entry Point (OEP) and jump to it
    mov rbx, [rbp + (delta - payload)]  ; rbx = delta (stored offset to OEP)
    add rbx, rbp                        ; rbx = original entry point (absolute)
    jmp rbx
```

### 4. Structure du payload

```txt
+--------------------+
| stage_load.asm     | --> call payload_main
|                    | --> jmp OriginalEntryPoint
+--------------------+
| payload_main       | --> MessageBoxA()
+--------------------+
| end_stub.asm       |
+--------------------+
```

### 5. Fonctionnement du payload

La charge utile du payload se trouve dans le fichier `payload.c`. Elle est appelée par le shellcode injecté et affiche une `MessageBoxA` avant de retourner à l'OEP original.

Dans cette partie du code, l'on va chercher à récupérer l'adresse de la fonction `MessageBoxA` dans le module `user32.dll` et l'appeler avec les paramètres appropriés.

Il y a plusieurs étapes nécessaires pour cela :

* Récupérer le handle du module `kernel32.dll` pour utiliser les fonctions :
  * `GetProcAddress`
  * `LoadLibraryA`
* Charger le module `user32.dll` en mémoire.
* Récupérer l'adresse de la fonction `MessageBoxA` dans le module `user32.dll`.
* Appeler la fonction `MessageBoxA` avec les paramètres appropriés.

---

## Protection

Le payload injecté est ni chiffré ni obfusqué. Cependant, il dispose d'une détection basique de son environment d'exécution, lui permettant ainsi de savoir s'il est éxécuté dans une machine virtuelle ou non.

```asm
_next:
    ...

    ; Check if running in a VM
    xor eax, eax
    inc eax
    cpuid
    bt ecx, 31           ; check hypervisor bit
    jz _not_vm           ; if not set, jump to not_vm

    ; If running in a VM, call main_payload with 1 argument
    mov rcx, 1           ; set rcx to 1 to indicate VM
    call main_payload

    jmp _restore_state

_not_vm:
    mov rcx, 0           ; set rcx to 0 to indicate non-VM
    call main_payload
```

---

## Exemple d'utilisation

```sh
yharnam.exe target.exe
```

Génère un `target.exe` infecté contenant la nouvelle section ".inj" et le shellcode.

---

## Auteur

Voir `AUTHORS.txt`.
