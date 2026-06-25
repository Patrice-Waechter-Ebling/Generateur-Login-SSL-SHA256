#### Generateur-Login-SSL-SHA256
  1. Un salt aléatoire de 16 octets empêche les attaques par rainbow tables.
  2. PBKDF2-HMAC-SHA256, dérive une clé AES‑256 à partir du mot de passe.
  3. AES‑256‑CBC, chiffre le log avec un IV aléatoire.
  4. Log final chiffré sous forme hexadécimale.
#### Methode SSL
+ Sans OpenSSL
+ MCE20 “maison” (implémentation pédagogique)
+ Dérivation de clé à partir username + password + salt (SHA‑256 maison)
+ Chiffrement + déchiffrement intégrés
+ Stockage des logs chiffrés dans un fichier
<img width="1366" height="391" alt="image" src="https://github.com/user-attachments/assets/f819c3c5-d67a-4b17-b568-bfbd96ca4a26" />
