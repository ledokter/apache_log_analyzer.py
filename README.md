# 🌐 Apache Log Analyzer with IP Geolocation

Analyseur de logs Apache en Python avec **enrichissement géographique** via IPInfo.io. Identifiez d'où viennent vos visiteurs, détectez les attaques, et générez des statistiques détaillées de votre trafic web.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Fonctionnalités

### 📊 Analyse Complète

- ✅ **Parse les logs Apache** (format Combined Log)
- ✅ **Géolocalisation IP** via IPInfo.io (pays, ville, FAI, coordonnées GPS)
- ✅ **Statistiques avancées** (top pays, villes, IPs, codes HTTP, etc.)
- ✅ **Filtres puissants** (date, IP, code HTTP, User-Agent)
- ✅ **Export CSV/JSON** pour analyse dans Excel, Tableau, etc.
- ✅ **Cache IP intelligent** (économise les appels API)
- ✅ **Interface colorée** avec indicateurs visuels
- ✅ **Mode interactif** ou **ligne de commande**

### 🎯 Cas d'Usage

| Usage | Description |
|-------|-------------|
| **🛡️ Sécurité** | Détecter les attaques DDoS, tentatives de bruteforce, scans de vulnérabilités |
| **🌍 Analytics** | Analyser l'origine géographique de votre trafic |
| **🤖 Bot Detection** | Identifier les bots, crawlers, scrapers |
| **📈 Performance** | Analyser les codes 404, 500, temps de réponse |
| **🔍 Forensics** | Investiguer après une intrusion |
| **📊 Reporting** | Générer des rapports pour clients/managers |

## 📋 Prérequis

### Système

- **Python** 3.7+
- **Apache** ou **Nginx** (avec logs au format Combined)
- Accès en lecture aux logs (permissions)

### Compte IPInfo.io

**Gratuit** (recommandé) :
- 50 000 requêtes/mois
- Inscription : https://ipinfo.io/signup

**Ou mode sans géolocalisation** avec `--no-geoip`

## 🚀 Installation

### Méthode 1 : Clone du Dépôt

```bash
# Cloner le projet
git clone https://github.com/votre-username/apache-log-analyzer.git
cd apache-log-analyzer

# Installer les dépendances
pip install -r requirements.txt

# Rendre exécutable (optionnel)
chmod +x apache_log_analyzer.py
Méthode 2 : Téléchargement Direct
bash
# Télécharger le script
wget https://raw.githubusercontent.com/votre-username/apache-log-analyzer/main/apache_log_analyzer.py

# Installer requests
pip install requests

# Exécuter
python apache_log_analyzer.py
Méthode 3 : Virtual Environment (Recommandé)
bash
# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r requirements.txt

# Exécuter
python apache_log_analyzer.py
💻 Utilisation
Mode Interactif (Recommandé pour Débutants)
bash
python apache_log_analyzer.py
Le script vous guidera à travers :

Sélection du fichier log (par domaine, chemin spécifique, ou custom)

Configuration du token IPInfo (ou mode sans géolocalisation)

Configuration des filtres (date, IP, status, User-Agent)

Options d'affichage (détaillé, stats, export)

Mode Ligne de Commande (Rapide)
Analyse Basique
bash
# Analyse simple avec géolocalisation
python apache_log_analyzer.py \
  --logfile /var/log/apache2/access.log \
  --token VOTRE_TOKEN_IPINFO

# Sans géolocalisation (plus rapide)
python apache_log_analyzer.py \
  --logfile /var/log/apache2/access.log \
  --no-geoip
Avec Filtres
bash
# Analyser uniquement les erreurs 404
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --status 404

# Analyser une IP spécifique
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --filter-ip 192.168.1.100

# Analyser une période
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --start-date "03/Feb/2026:00:00" \
  --end-date "03/Feb/2026:23:59"
Avec Exports
bash
# Export CSV
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --export-csv rapport.csv

# Export JSON + CSV
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --export-csv data.csv \
  --export-json data.json

# Statistiques uniquement (pas de détails)
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --stats-only
Exemples Concrets
1. Détecter une Attaque DDoS
bash
# Analyser les IPs avec le plus de requêtes
python apache_log_analyzer.py \
  --logfile /var/log/apache2/access.log \
  --token TOKEN \
  --stats-only

# Regarder la section "Top 10 IPs"
# Si une IP a 10x plus de requêtes que les autres → suspect
2. Identifier les Tentatives de Bruteforce
bash
# Analyser les tentatives de connexion échouées
python apache_log_analyzer.py \
  --logfile /var/log/apache2/access.log \
  --token TOKEN \
  --status 401 \
  --export-csv bruteforce.csv

# Ouvrir bruteforce.csv et trier par IP
# IPs avec 100+ tentatives → bruteforce
3. Audit de Sécurité (404 suspects)
bash
# Chercher les scans de vulnérabilités
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --status 404

# Chercher dans les URLs :
# - /admin, /phpmyadmin, /wp-admin (si pas WordPress)
# - .php, .asp sur un site statique
# - Tentatives d'injection SQL
4. Analyse Géographique du Trafic
bash
# Générer un rapport avec pays/villes
python apache_log_analyzer.py \
  --logfile access.log \
  --token TOKEN \
  --export-json geo-report.json

# Ouvrir geo-report.json
# Section "top_countries" et "top_cities"
5. Monitoring Quotidien (Cron)
bash
# Ajouter dans crontab -e
# Rapport quotidien à 23h59
59 23 * * * /usr/bin/python3 /opt/scripts/apache_log_analyzer.py \
  --logfile /var/log/apache2/access.log \
  --token YOUR_TOKEN \
  --stats-only \
  --export-csv /var/reports/daily-$(date +\%Y\%m\%d).csv
📊 Format de Sortie
Affichage Détaillé
text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entrée #1234
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 IP          : 93.184.216.34
🕒 Date/Heure  : 03/Feb/2026:04:15:30 +0100
📝 Méthode     : GET
🔗 URL         : /blog/article-securite
📊 Status HTTP : 200
📏 Taille      : 45321 bytes
🔙 Referer     : https://www.google.com/search?q=securite+web
🖥️  User-Agent  : Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0...

📍 Géolocalisation :
   🌍 Pays      : FR
   🏙️  Ville     : Paris
   📌 Région    : Île-de-France
   🏢 Org/ISP   : AS3215 Orange S.A.
   📮 Code Post.: 75001
   🌐 Coord.    : 48.8566,2.3522
   ⏰ Timezone  : Europe/Paris
Statistiques Globales
text
═══════════════════════════════════════════════════════════════
📊 STATISTIQUES GLOBALES
═══════════════════════════════════════════════════════════════

📋 Résumé Général
   Lignes totales        : 125,432
   Lignes parsées        : 124,891
   Lignes filtrées       : 124,891
   IPs uniques           : 3,421

🔢 Top 10 Codes HTTP
   200 : 98,234 requêtes
   404 : 15,432 requêtes
   301 : 8,543 requêtes
   500 : 1,234 requêtes
   403 : 876 requêtes

🌍 Top 10 Pays
   FR : 45,678 visites
   US : 32,123 visites
   DE : 12,345 visites
   GB : 8,765 visites
   CA : 5,432 visites

🏢 Top 10 Organisations/ISP
   AS3215 Orange S.A. : 12,345 visites
   AS15169 Google LLC : 9,876 visites
   AS5576 Bouygues Telecom : 7,654 visites

🌐 Top 10 IPs (par nombre de requêtes)
   93.184.216.34 : 1,234 requêtes
   198.51.100.10 : 987 requêtes
Export CSV
Colonnes :

IP, DateTime, Method, URL, Status, Size

Referer, UserAgent

Country, City, Region, Org, Postal, Coordinates, Timezone

Export JSON
Structure :

json
{
  "metadata": {
    "version": "1.0.0",
    "timestamp": "2026-02-03T04:30:00",
    "total_entries": 1234
  },
  "statistics": {
    "total_lines": 125432,
    "top_countries": {"FR": 45678, "US": 32123},
    "status_codes": {"200": 98234, "404": 15432}
  },
  "entries": [
    {
      "log_data": {...},
      "geo_data": {...}
    }
  ]
}
🔐 Sécurité et Permissions
Accès aux Logs Apache
bash
# Option 1 : Ajouter votre user au groupe www-data
sudo usermod -a -G www-data $USER
sudo chmod g+r /var/log/apache2/*.log

# Option 2 : Exécuter avec sudo
sudo python apache_log_analyzer.py --logfile /var/log/apache2/access.log

# Option 3 : Copier les logs dans votre home
sudo cp /var/log/apache2/access.log ~/access.log
sudo chown $USER:$USER ~/access.log
Sécuriser le Token IPInfo
bash
# Méthode 1 : Variable d'environnement
export IPINFO_TOKEN="votre_token_ici"
python apache_log_analyzer.py --logfile access.log --token $IPINFO_TOKEN

# Méthode 2 : Fichier de config (ajouté au .gitignore)
cp config.example.ini config.ini
# Éditer config.ini avec votre token
🛠️ Configuration Apache
Format Combined Log (Standard)
Vérifier dans /etc/apache2/apache2.conf :

text
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined

<VirtualHost *:80>
    ServerName example.com
    CustomLog /var/log/apache2/example.com-access.log combined
    ErrorLog /var/log/apache2/example.com-error.log
</VirtualHost>
Logs par Domaine (Multisite)
text
<VirtualHost *:80>
    ServerName site1.com
    CustomLog /var/log/apache2/site1.com-access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName site2.com
    CustomLog /var/log/apache2/site2.com-access.log combined
</VirtualHost>
Rotation des Logs (Logrotate)
Créer /etc/logrotate.d/apache2-custom :

text
/var/log/apache2/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /etc/init.d/apache2 reload > /dev/null
    endscript
}
📈 Cas d'Usage Avancés
1. Détection d'Anomalies avec Script Bash
bash
#!/bin/bash
# anomaly_detector.sh

LOGFILE="/var/log/apache2/access.log"
TOKEN="YOUR_TOKEN"
THRESHOLD=1000

# Analyser les stats
python apache_log_analyzer.py \
  --logfile $LOGFILE \
  --token $TOKEN \
  --stats-only \
  --export-json /tmp/stats.json

# Extraire le top IP
TOP_IP_COUNT=$(jq '.statistics.top_ips[1]' /tmp/stats.json)

# Alerter si anomalie
if [ $TOP_IP_COUNT -gt $THRESHOLD ]; then
    echo "⚠️ ALERTE : $TOP_IP_COUNT requêtes détectées depuis une IP !" | \
    mail -s "DDoS Alert" admin@example.com
fi
2. Dashboard avec Grafana + InfluxDB
python
# Ajouter dans le script après l'analyse
from influxdb import InfluxDBClient

client = InfluxDBClient(host='localhost', port=8086, database='apache_logs')

for entry in entries:
    point = {
        "measurement": "http_requests",
        "tags": {
            "status": entry['data']['status'],
            "country": entry['ipinfo'].get('country', 'Unknown'),
            "method": entry['data'].get('method', 'UNKNOWN')
        },
        "fields": {
            "value": 1
        }
    }
    client.write_points([point])
3. Intégration avec Slack
python
# Ajouter après l'analyse
import requests

def send_slack_alert(message):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    payload = {"text": message}
    requests.post(webhook_url, json=payload)

# Détecter attaques
if stats['ips'].most_common(1)[1] > 1000:
    top_ip = stats['ips'].most_common(1)
    send_slack_alert(f"🚨 Possible DDoS from {top_ip}")
4. Analyse Multi-Domaines
bash
#!/bin/bash
# analyze_all_domains.sh

DOMAINS=(
    "site1.com"
    "site2.com"
    "site3.com"
)

TOKEN="YOUR_TOKEN"

for domain in "${DOMAINS[@]}"; do
    echo "=== Analyse de $domain ==="
    python apache_log_analyzer.py \
        --logfile /var/log/apache2/${domain}-access.log \
        --token $TOKEN \
        --stats-only \
        --export-csv /var/reports/${domain}-$(date +%Y%m%d).csv
done
🐛 Résolution de Problèmes
Problème : "Permission denied"
Solution :

bash
# Option 1
sudo chmod +r /var/log/apache2/access.log

# Option 2
sudo python apache_log_analyzer.py --logfile /var/log/apache2/access.log
Problème : "Quota API dépassé"
Solutions :

Réduire la fréquence d'analyse

Filtrer les logs (--status, --start-date)

Utiliser --no-geoip pour tests

Passer à un plan IPInfo payant

Problème : "Aucune ligne parsée"
Causes :

Format de log non-standard

Fichier vide ou corrompu

Solution :

bash
# Vérifier le format
head -1 /var/log/apache2/access.log

# Doit ressembler à :
# 93.184.216.34 - - [03/Feb/2026:04:15:30 +0100] "GET / HTTP/1.1" 200 5432 "https://google.com" "Mozilla/5.0..."
Problème : Script lent
Solutions :

Filtrer par date (--start-date)

Limiter les lignes (--max-lines 1000)

Utiliser --stats-only

Désactiver géolocalisation (--no-geoip)

📚 Ressources
Documentation
Apache Log Files

IPInfo API Documentation

Python Requests

Outils Complémentaires
GoAccess - Analyseur de logs en temps réel

AWStats - Statistiques web avancées

Fail2Ban - Protection contre bruteforce

🤝 Contribution
Les contributions sont bienvenues !

Comment Contribuer
Fork le projet

Créer une branche : git checkout -b feature/amelioration

Commit : git commit -m "Ajout détection VPN/Proxy"

Push : git push origin feature/amelioration

Ouvrir une Pull Request

Idées d'Améliorations
 Support Nginx logs

 Détection automatique VPN/Proxy (IPInfo Privacy)

 Génération de graphiques (matplotlib)

 Interface web (Flask/FastAPI)

 Support IPv6

 Database storage (SQLite/PostgreSQL)

 Machine Learning pour anomaly detection

 Multi-threading pour gros fichiers

 Support compressed logs (.gz)

📝 Changelog
v1.0.0 (2026-02-03)
🎉 Version initiale

✨ Parse logs Apache (Combined Log Format)

✨ Géolocalisation via IPInfo.io

✨ Statistiques avancées

✨ Filtres (date, IP, status, User-Agent)

✨ Export CSV/JSON

✨ Mode interactif

✨ Cache IP

✨ Interface colorée

⚖️ Licence
MIT License

LEDOKTER

⭐ Si cet outil vous aide, donnez une étoile au projet !
