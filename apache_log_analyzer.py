#!/usr/bin/env python3
"""
Apache Log Analyzer with IP Geolocation
Analyse les logs Apache et enrichit les données avec la géolocalisation IPInfo
"""

import re
import requests
import argparse
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime
import json
import csv

# Configuration
VERSION = "1.0.0"
DEFAULT_LOG_PATH = "/var/log/apache2/"
IPINFO_API_URL = "https://ipinfo.io"

class Colors:
    """Couleurs pour l'affichage terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Affiche le banner ASCII"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🌐  Apache Log Analyzer with IP Geolocation               ║
║       Version {VERSION}                                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_success(message):
    """Affiche un message de succès"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_error(message):
    """Affiche un message d'erreur"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def print_warning(message):
    """Affiche un avertissement"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_info(message):
    """Affiche une information"""
    print(f"{Colors.CYAN}ℹ️  {message}{Colors.END}")

def get_logfile_path():
    """Demande le chemin du fichier log"""
    print(f"\n{Colors.BOLD}📁 CHEMIN DU FICHIER LOG{Colors.END}")
    print("")
    print("Options :")
    print("  1) Fichier log spécifique (ex: /var/log/apache2/access.log)")
    print("  2) Fichier par nom de domaine (ex: monsite.com)")
    print("  3) Chemin personnalisé")
    print("")
    
    choice = input("Sélectionnez une option [1] : ").strip() or "1"
    
    if choice == "1":
        log_path = input(f"Chemin du fichier log [{DEFAULT_LOG_PATH}access.log] : ").strip()
        if not log_path:
            log_path = f"{DEFAULT_LOG_PATH}access.log"
    elif choice == "2":
        domain = input("Nom de domaine (ex: example.com) : ").strip()
        if not domain:
            print_error("Le nom de domaine est requis")
            sys.exit(1)
        log_path = f"{DEFAULT_LOG_PATH}{domain}-access.log"
    else:
        log_path = input("Chemin complet du fichier log : ").strip()
        if not log_path:
            print_error("Le chemin est requis")
            sys.exit(1)
    
    if not os.path.exists(log_path):
        print_error(f"Le fichier {log_path} n'existe pas")
        
        # Suggérer des fichiers existants
        log_dir = os.path.dirname(log_path) or DEFAULT_LOG_PATH
        if os.path.exists(log_dir):
            log_files = [f for f in os.listdir(log_dir) if 'access' in f and f.endswith('.log')]
            if log_files:
                print_info("Fichiers disponibles dans ce répertoire :")
                for f in log_files[:10]:
                    print(f"  • {os.path.join(log_dir, f)}")
        sys.exit(1)
    
    print_success(f"Fichier log : {log_path}")
    return log_path

def get_ipinfo_token():
    """Demande le token IPInfo"""
    print(f"\n{Colors.BOLD}🔑 TOKEN API IPINFO.IO{Colors.END}")
    print("")
    print("Pour obtenir un token gratuit (50 000 requêtes/mois) :")
    print("  1. Aller sur https://ipinfo.io/signup")
    print("  2. Créer un compte gratuit")
    print("  3. Copier votre token d'accès")
    print("")
    
    token = input("Token IPInfo.io : ").strip()
    
    if not token:
        print_error("Le token est requis pour l'enrichissement géographique")
        print_info("Vous pouvez utiliser le script sans token avec --no-geoip")
        sys.exit(1)
    
    # Vérifier la validité du token
    try:
        response = requests.get(f"{IPINFO_API_URL}/8.8.8.8?token={token}", timeout=5)
        if response.status_code == 200:
            print_success("Token validé avec succès")
            return token
        elif response.status_code == 401:
            print_error("Token invalide")
            sys.exit(1)
        else:
            print_warning(f"Impossible de valider le token (code {response.status_code})")
            return token
    except Exception as e:
        print_warning(f"Impossible de valider le token : {e}")
        return token

def configure_filters():
    """Configure les filtres d'analyse"""
    print(f"\n{Colors.BOLD}🔍 FILTRES (OPTIONNELS){Colors.END}")
    print("")
    
    filters = {}
    
    # Filtre par date
    print("Filtrer par date/heure ?")
    start_date = input("  Date de début (format: 03/Feb/2026:04:15 ou vide) : ").strip()
    end_date = input("  Date de fin (format: 03/Feb/2026:05:30 ou vide) : ").strip()
    
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date
    
    # Filtre par IP
    filter_ip = input("\nFiltrer par IP spécifique (ou vide) : ").strip()
    if filter_ip:
        filters['ip'] = filter_ip
    
    # Filtre par code HTTP
    print("\nFiltrer par code HTTP ?")
    print("  Exemples : 200 (succès), 404 (non trouvé), 500 (erreur serveur)")
    status_code = input("  Code HTTP (ou vide) : ").strip()
    if status_code:
        filters['status'] = status_code
    
    # Filtre User-Agent
    print("\nFiltrer par User-Agent ?")
    print("  Exemples : bot, curl, chrome, mobile")
    user_agent = input("  Texte à rechercher (ou vide) : ").strip()
    if user_agent:
        filters['user_agent'] = user_agent.lower()
    
    return filters

def configure_output():
    """Configure les options de sortie"""
    print(f"\n{Colors.BOLD}📊 OPTIONS D'AFFICHAGE{Colors.END}")
    print("")
    
    options = {}
    
    # Mode d'affichage
    print("Mode d'affichage :")
    print("  1) Détaillé (chaque requête)")
    print("  2) Statistiques uniquement")
    print("  3) Les deux")
    display_mode = input("Sélectionnez [3] : ").strip() or "3"
    options['detailed'] = display_mode in ["1", "3"]
    options['stats'] = display_mode in ["2", "3"]
    
    # Limite d'affichage
    if options['detailed']:
        max_lines = input("\nNombre maximum de lignes à afficher (0 = toutes) [100] : ").strip()
        options['max_lines'] = int(max_lines) if max_lines else 100
    else:
        options['max_lines'] = 0
    
    # Export
    print("\nExporter les résultats ?")
    export = input("  Exporter en CSV ? (o/n) [n] : ").strip().lower()
    if export == 'o':
        csv_file = input("  Nom du fichier CSV [output.csv] : ").strip() or "output.csv"
        options['export_csv'] = csv_file
    
    export_json = input("  Exporter en JSON ? (o/n) [n] : ").strip().lower()
    if export_json == 'o':
        json_file = input("  Nom du fichier JSON [output.json] : ").strip() or "output.json"
        options['export_json'] = json_file
    
    return options

def parse_apache_log_line(line):
    """
    Parse une ligne de log Apache au format Combined
    Format : IP - - [datetime] "request" status size "referer" "useragent"
    """
    # Format Combined Log
    pattern = (
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
        r'"(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"'
    )
    match = re.match(pattern, line)
    if match:
        data = match.groupdict()
        # Parser la requête (method url protocol)
        request_parts = data['request'].split(' ', 2)
        if len(request_parts) >= 2:
            data['method'] = request_parts[0]
            data['url'] = request_parts[1]
            data['protocol'] = request_parts[2] if len(request_parts) > 2 else ''
        return data
    return None

def ipinfo_lookup(ip, token, cache):
    """
    Récupère les informations géographiques d'une IP via IPInfo
    """
    if ip in cache:
        return cache[ip]
    
    url = f"{IPINFO_API_URL}/{ip}?token={token}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            cache[ip] = data
            return data
        elif resp.status_code == 429:
            print_warning(f"Quota API dépassé pour {ip}")
            cache[ip] = {'error': 'rate_limit'}
            return cache[ip]
    except Exception as e:
        print_warning(f"Erreur IPInfo pour {ip}: {e}")
    
    cache[ip] = {}
    return cache[ip]

def apply_filters(data, filters):
    """Vérifie si une entrée correspond aux filtres"""
    if not filters:
        return True
    
    # Filtre date de début
    if 'start_date' in filters:
        if data['datetime'] < filters['start_date']:
            return False
    
    # Filtre date de fin
    if 'end_date' in filters:
        if data['datetime'] > filters['end_date']:
            return False
    
    # Filtre IP
    if 'ip' in filters:
        if data['ip'] != filters['ip']:
            return False
    
    # Filtre status
    if 'status' in filters:
        if data['status'] != filters['status']:
            return False
    
    # Filtre User-Agent
    if 'user_agent' in filters:
        if filters['user_agent'] not in data['useragent'].lower():
            return False
    
    return True

def analyze_logs(logfile, token, filters, options, use_geoip=True):
    """Analyse principale des logs"""
    print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}📊 ANALYSE EN COURS{Colors.END}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}\n")
    
    ip_cache = {}
    entries = []
    
    # Statistiques
    stats = {
        'total_lines': 0,
        'parsed_lines': 0,
        'filtered_lines': 0,
        'countries': Counter(),
        'cities': Counter(),
        'orgs': Counter(),
        'status_codes': Counter(),
        'methods': Counter(),
        'urls': Counter(),
        'user_agents': Counter(),
        'ips': Counter(),
    }
    
    print_info(f"Lecture du fichier : {logfile}")
    print("")
    
    try:
        with open(logfile, "r", encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stats['total_lines'] += 1
                
                # Progress indicator
                if line_num % 1000 == 0:
                    print(f"\r{Colors.CYAN}  Lignes traitées : {line_num}{Colors.END}", end='', flush=True)
                
                # Parser la ligne
                data = parse_apache_log_line(line)
                if not data:
                    continue
                
                stats['parsed_lines'] += 1
                
                # Appliquer les filtres
                if not apply_filters(data, filters):
                    continue
                
                stats['filtered_lines'] += 1
                
                # Enrichir avec IPInfo
                ipinfo = {}
                if use_geoip and token:
                    ip = data['ip']
                    ipinfo = ipinfo_lookup(ip, token, ip_cache)
                
                # Collecter les statistiques
                stats['status_codes'][data['status']] += 1
                stats['methods'][data.get('method', 'UNKNOWN')] += 1
                stats['ips'][data['ip']] += 1
                
                if ipinfo and 'error' not in ipinfo:
                    stats['countries'][ipinfo.get('country', 'Unknown')] += 1
                    stats['cities'][ipinfo.get('city', 'Unknown')] += 1
                    stats['orgs'][ipinfo.get('org', 'Unknown')] += 1
                
                # Stocker pour affichage détaillé
                entry = {
                    'data': data,
                    'ipinfo': ipinfo
                }
                entries.append(entry)
                
                # Affichage détaillé en temps réel (si activé et sous la limite)
                if options.get('detailed') and (options['max_lines'] == 0 or len(entries) <= options['max_lines']):
                    print_entry(entry, line_num)
        
        print(f"\n\n{Colors.GREEN}✅ Analyse terminée{Colors.END}\n")
        
    except FileNotFoundError:
        print_error(f"Fichier non trouvé : {logfile}")
        sys.exit(1)
    except PermissionError:
        print_error(f"Permission refusée pour lire : {logfile}")
        print_info("Essayez avec sudo ou vérifiez les permissions")
        sys.exit(1)
    except Exception as e:
        print_error(f"Erreur lors de la lecture : {e}")
        sys.exit(1)
    
    return entries, stats

def print_entry(entry, line_num):
    """Affiche une entrée de log enrichie"""
    data = entry['data']
    ipinfo = entry['ipinfo']
    
    print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}")
    print(f"{Colors.CYAN}Entrée #{line_num}{Colors.END}")
    print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}")
    
    # Données de base
    print(f"🌐 IP          : {Colors.BOLD}{data['ip']}{Colors.END}")
    print(f"🕒 Date/Heure  : {data['datetime']}")
    print(f"📝 Méthode     : {data.get('method', 'N/A')}")
    print(f"🔗 URL         : {data.get('url', 'N/A')}")
    print(f"📊 Status HTTP : {get_status_color(data['status'])}{data['status']}{Colors.END}")
    print(f"📏 Taille      : {data['size']} bytes")
    print(f"🔙 Referer     : {data['referer'] if data['referer'] != '-' else 'Direct'}")
    print(f"🖥️  User-Agent  : {data['useragent'][:80]}...")
    
    # Données géographiques
    if ipinfo and 'error' not in ipinfo:
        print(f"\n{Colors.YELLOW}📍 Géolocalisation :{Colors.END}")
        print(f"   🌍 Pays      : {ipinfo.get('country', 'N/A')}")
        print(f"   🏙️  Ville     : {ipinfo.get('city', 'N/A')}")
        print(f"   📌 Région    : {ipinfo.get('region', 'N/A')}")
        print(f"   🏢 Org/ISP   : {ipinfo.get('org', 'N/A')}")
        print(f"   📮 Code Post.: {ipinfo.get('postal', 'N/A')}")
        print(f"   🌐 Coord.    : {ipinfo.get('loc', 'N/A')}")
        print(f"   ⏰ Timezone  : {ipinfo.get('timezone', 'N/A')}")
    elif ipinfo and ipinfo.get('error') == 'rate_limit':
        print(f"\n{Colors.YELLOW}⚠️  Quota API dépassé{Colors.END}")
    
    print("")

def get_status_color(status):
    """Retourne la couleur selon le code HTTP"""
    status_int = int(status)
    if 200 <= status_int < 300:
        return Colors.GREEN
    elif 300 <= status_int < 400:
        return Colors.CYAN
    elif 400 <= status_int < 500:
        return Colors.YELLOW
    else:
        return Colors.RED

def print_statistics(stats):
    """Affiche les statistiques globales"""
    print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}📊 STATISTIQUES GLOBALES{Colors.END}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}\n")
    
    # Résumé général
    print(f"{Colors.CYAN}📋 Résumé Général{Colors.END}")
    print(f"   Lignes totales        : {stats['total_lines']:,}")
    print(f"   Lignes parsées        : {stats['parsed_lines']:,}")
    print(f"   Lignes filtrées       : {stats['filtered_lines']:,}")
    print(f"   IPs uniques           : {len(stats['ips']):,}")
    print("")
    
    # Top codes HTTP
    if stats['status_codes']:
        print(f"{Colors.CYAN}🔢 Top 10 Codes HTTP{Colors.END}")
        for status, count in stats['status_codes'].most_common(10):
            print(f"   {get_status_color(status)}{status}{Colors.END} : {count:,} requêtes")
        print("")
    
    # Top méthodes HTTP
    if stats['methods']:
        print(f"{Colors.CYAN}📝 Méthodes HTTP{Colors.END}")
        for method, count in stats['methods'].most_common():
            print(f"   {method} : {count:,} requêtes")
        print("")
    
    # Top pays
    if stats['countries']:
        print(f"{Colors.CYAN}🌍 Top 10 Pays{Colors.END}")
        for country, count in stats['countries'].most_common(10):
            print(f"   {country} : {count:,} visites")
        print("")
    
    # Top villes
    if stats['cities']:
        print(f"{Colors.CYAN}🏙️  Top 10 Villes{Colors.END}")
        for city, count in stats['cities'].most_common(10):
            print(f"   {city} : {count:,} visites")
        print("")
    
    # Top organisations/ISP
    if stats['orgs']:
        print(f"{Colors.CYAN}🏢 Top 10 Organisations/ISP{Colors.END}")
        for org, count in stats['orgs'].most_common(10):
            org_short = org[:60] + '...' if len(org) > 60 else org
            print(f"   {org_short} : {count:,} visites")
        print("")
    
    # Top IPs
    print(f"{Colors.CYAN}🌐 Top 10 IPs (par nombre de requêtes){Colors.END}")
    for ip, count in stats['ips'].most_common(10):
        print(f"   {ip} : {count:,} requêtes")
    print("")

def export_to_csv(entries, filename):
    """Exporte les résultats en CSV"""
    print_info(f"Export CSV vers : {filename}")
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'IP', 'DateTime', 'Method', 'URL', 'Status', 'Size', 
                'Referer', 'UserAgent', 'Country', 'City', 'Region', 
                'Org', 'Postal', 'Coordinates', 'Timezone'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for entry in entries:
                data = entry['data']
                ipinfo = entry['ipinfo']
                
                row = {
                    'IP': data['ip'],
                    'DateTime': data['datetime'],
                    'Method': data.get('method', ''),
                    'URL': data.get('url', ''),
                    'Status': data['status'],
                    'Size': data['size'],
                    'Referer': data['referer'],
                    'UserAgent': data['useragent'],
                    'Country': ipinfo.get('country', ''),
                    'City': ipinfo.get('city', ''),
                    'Region': ipinfo.get('region', ''),
                    'Org': ipinfo.get('org', ''),
                    'Postal': ipinfo.get('postal', ''),
                    'Coordinates': ipinfo.get('loc', ''),
                    'Timezone': ipinfo.get('timezone', ''),
                }
                writer.writerow(row)
        
        print_success(f"Export CSV terminé : {filename}")
    except Exception as e:
        print_error(f"Erreur lors de l'export CSV : {e}")

def export_to_json(entries, stats, filename):
    """Exporte les résultats en JSON"""
    print_info(f"Export JSON vers : {filename}")
    
    try:
        output = {
            'metadata': {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'total_entries': len(entries),
            },
            'statistics': {
                'total_lines': stats['total_lines'],
                'parsed_lines': stats['parsed_lines'],
                'filtered_lines': stats['filtered_lines'],
                'unique_ips': len(stats['ips']),
                'top_countries': dict(stats['countries'].most_common(10)),
                'top_cities': dict(stats['cities'].most_common(10)),
                'status_codes': dict(stats['status_codes']),
                'methods': dict(stats['methods']),
            },
            'entries': [
                {
                    'log_data': entry['data'],
                    'geo_data': entry['ipinfo']
                }
                for entry in entries
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(output, jsonfile, indent=2, ensure_ascii=False)
        
        print_success(f"Export JSON terminé : {filename}")
    except Exception as e:
        print_error(f"Erreur lors de l'export JSON : {e}")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Analyseur de logs Apache avec géolocalisation IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation :
  
  Mode interactif (recommandé) :
    python apache_log_analyzer.py
  
  Mode rapide avec arguments :
    python apache_log_analyzer.py --logfile /var/log/apache2/access.log --token VOTRE_TOKEN
  
  Sans géolocalisation :
    python apache_log_analyzer.py --logfile access.log --no-geoip
  
  Avec filtres :
    python apache_log_analyzer.py --logfile access.log --token TOKEN --status 404
    python apache_log_analyzer.py --logfile access.log --token TOKEN --filter-ip 192.168.1.1
        """
    )
    
    parser.add_argument('--logfile', help="Chemin du fichier log Apache")
    parser.add_argument('--token', help="Token API IPInfo.io")
    parser.add_argument('--no-geoip', action='store_true', help="Désactiver la géolocalisation")
    parser.add_argument('--status', help="Filtrer par code HTTP (ex: 404)")
    parser.add_argument('--filter-ip', help="Filtrer par IP spécifique")
    parser.add_argument('--start-date', help="Date de début (format: 03/Feb/2026:04:15)")
    parser.add_argument('--end-date', help="Date de fin")
    parser.add_argument('--max-lines', type=int, default=100, help="Nombre max de lignes à afficher (0=toutes)")
    parser.add_argument('--stats-only', action='store_true', help="Afficher uniquement les statistiques")
    parser.add_argument('--export-csv', help="Exporter en CSV")
    parser.add_argument('--export-json', help="Exporter en JSON")
    parser.add_argument('--version', action='version', version=f'Apache Log Analyzer v{VERSION}')
    
    args = parser.parse_args()
    
    # Banner
    print_banner()
    
    # Mode interactif ou arguments
    if not args.logfile:
        logfile = get_logfile_path()
    else:
        logfile = args.logfile
        if not os.path.exists(logfile):
            print_error(f"Fichier non trouvé : {logfile}")
            sys.exit(1)
        print_success(f"Fichier log : {logfile}")
    
    # Token IPInfo
    use_geoip = not args.no_geoip
    token = None
    
    if use_geoip:
        if not args.token:
            token = get_ipinfo_token()
        else:
            token = args.token
            print_success("Token IPInfo fourni")
    else:
        print_info("Mode sans géolocalisation activé")
    
    # Filtres
    if args.status or args.filter_ip or args.start_date or args.end_date:
        filters = {}
        if args.status:
            filters['status'] = args.status
        if args.filter_ip:
            filters['ip'] = args.filter_ip
        if args.start_date:
            filters['start_date'] = args.start_date
        if args.end_date:
            filters['end_date'] = args.end_date
        print_success(f"Filtres appliqués : {filters}")
    else:
        if not args.logfile:  # Mode interactif
            filters = configure_filters()
        else:
            filters = {}
    
    # Options d'affichage
    if args.stats_only or args.export_csv or args.export_json:
        options = {
            'detailed': not args.stats_only,
            'stats': True,
            'max_lines': args.max_lines,
            'export_csv': args.export_csv,
            'export_json': args.export_json,
        }
    else:
        if not args.logfile:  # Mode interactif
            options = configure_output()
        else:
            options = {
                'detailed': True,
                'stats': True,
                'max_lines': args.max_lines,
            }
    
    # Analyse
    entries, stats = analyze_logs(logfile, token, filters, options, use_geoip)
    
    # Statistiques
    if options.get('stats', True):
        print_statistics(stats)
    
    # Exports
    if options.get('export_csv'):
        export_to_csv(entries, options['export_csv'])
    
    if options.get('export_json'):
        export_to_json(entries, stats, options['export_json'])
    
    # Résumé final
    print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.GREEN}✨ Analyse terminée avec succès !{Colors.END}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.END}\n")
    
    print_info(f"Entrées analysées : {len(entries):,}")
    if use_geoip:
        print_info(f"IPs géolocalisées : {len([e for e in entries if e['ipinfo'] and 'error' not in e['ipinfo']]):,}")

if __name__ == "__main__":
    main()
