# Snow Crash – Level09

## 🌟 Objectif
Lire un token chiffré dans un fichier à l'aide d'un binaire de déchiffrement.

---

## 💼 1. Situation initiale

```bash
level09@SnowCrash:~$ ls -l
total 12
-rwsr-sr-x 1 flag09 level09 7640 Mar  5  2016 level09
----r--r-- 1 flag09 level09   26 Mar  5  2016 token
```

- Le fichier `token` est lisible, mais contient des caractères illisibles.
- Le binaire `level09` demande un argument :

```bash
level09@SnowCrash:~$ ./level09
You need to provied only one arg.
```

---

## 🧠 2. Analyse du fonctionnement du binaire

### Exemple :
```bash
level09@SnowCrash:~$ ./level09 abcdefgh
acegikmo
```

Chaque caractère est modifié selon sa position dans la chaîne :

```text
"a" + 0 = a
"b" + 1 = c
"c" + 2 = e
...
```

On en déduit que l'encodage consiste à **ajouter l'index du caractère à son code ASCII**.

Donc pour **décoder**, il faut **soustraire l'index à chaque caractère**.

---

## 🔧 3. Création d'un programme de déchiffrement

```c
#include <stdio.h>
int main(int argc, char **argv) {
  char *arg;
  int i = 0;
  if (argc != 2) {
    fprintf(stderr, "[-] Only one argument is accepted\n");
    return 1;
  }
  arg = argv[1];
  while (*arg) {
    printf("%c", *arg - i);
    i++;
    arg++;
  }
  printf("\n");
  return 0;
}
```

Compilation :
```bash
cd /tmp
vim decode.c
# (Coller le code ci-dessus)
gcc decode.c -o decode
```

---

## 🔐 4. Récupération du mot de passe

```bash
level09@SnowCrash:~$ cat token | xargs /tmp/decode
f3iji1ju5yuevaus41q1afiuq
```

Ce token est le mot de passe de `flag09`.

Connexion :
```bash
level09@SnowCrash:~$ su flag09
Password: f3iji1ju5yuevaus41q1afiuq
```

Récupération du flag :
```bash
flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```

---

## ✅ Résumé

- 🔑 Mot de passe `flag09` : `f3iji1ju5yuevaus41q1afiuq`
- 🏆 Token : `s5cAJpM8ev6XHw998pRWG728z`
- 🔑 Mot de passe `level10` : `s5cAJpM8ev6XHw998pRWG728z`