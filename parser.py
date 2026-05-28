import pandas as pd
from io import StringIO

# ─────────────────────────────────────────────────────────────
# TABLE CVE — comportement → CVE associée
# ─────────────────────────────────────────────────────────────
CVE_MAP = {
    "BRUTEFORCE"           : {"cve":"CVE-2019-0708",  "cvss":9.8,  "epss":0.97, "desc":"Windows RDP Brute Force"},
    "ESCALADE_PRIVILEGES"  : {"cve":"CVE-2021-34527", "cvss":8.8,  "epss":0.95, "desc":"PrintNightmare - Escalade privileges"},
    "CONNEXION_NOCTURNE"   : {"cve":"CVE-2023-23397", "cvss":9.8,  "epss":0.88, "desc":"Microsoft Outlook - Connexion suspecte"},
    "CREATION_COMPTE"      : {"cve":"CVE-2020-1472",  "cvss":10.0, "epss":0.96, "desc":"Zerologon - Creation compte suspect"},
    "ENUMERATION_COMPTES"  : {"cve":"CVE-2021-36934", "cvss":7.8,  "epss":0.75, "desc":"Windows SAM - Enumeration comptes"},
    "LECTURE_CREDENTIALS"  : {"cve":"CVE-2022-26925", "cvss":8.1,  "epss":0.82, "desc":"Windows LSA - Vol de credentials"},
    "ACTIVITE_NOCTURNE"    : {"cve":"CVE-2023-23397", "cvss":9.8,  "epss":0.88, "desc":"Activite suspecte hors horaires"},
}

# ─────────────────────────────────────────────────────────────
# PARSER PRINCIPAL
# ─────────────────────────────────────────────────────────────
def parser_logs(source):
    """
    Lit un fichier CSV de logs Windows.
    Accepte un chemin fichier ou un objet StringIO.
    """
    try:
        df = pd.read_csv(source, encoding='utf-8', on_bad_lines='skip')
    except UnicodeDecodeError:
        df = pd.read_csv(source, encoding='latin-1', on_bad_lines='skip')
    except Exception:
        if hasattr(source, 'read'):
            source.seek(0)
            df = pd.read_csv(source, encoding='latin-1', on_bad_lines='skip')
        else:
            raise

    # Normaliser les noms de colonnes
    df.columns = [c.strip().lower().replace(' ','_') for c in df.columns]

    # Mapper les variantes de noms de colonnes
    rename_map = {
        'timecreated'  : 'time', 'time_created': 'time',
        'date'         : 'time', 'horodatage'  : 'time',
        'id'           : 'event_id', 'eventid'  : 'event_id',
        'machinename'  : 'machine', 'machine_name': 'machine',
        'ordinateur'   : 'machine',
        'username'     : 'user', 'user_name'   : 'user',
        'ipaddress'    : 'ip',  'ip_address'   : 'ip',
        'message'      : 'message',
    }
    df = df.rename(columns={k:v for k,v in rename_map.items() if k in df.columns})

    # Colonnes optionnelles
    for col in ['user','ip','message']:
        if col not in df.columns:
            df[col] = ''

    # Conversion des types
    df['time']     = pd.to_datetime(df['time'], dayfirst=True, errors='coerce')
    df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(0).astype(int)
    df             = df.dropna(subset=['time']).sort_values('time').reset_index(drop=True)

    print(f"[PARSER] {len(df)} evenements charges")
    print(f"[PARSER] Periode : {df['time'].min()} → {df['time'].max()}")
    print(f"[PARSER] Event IDs : {sorted(df['event_id'].unique())}")
    return df


def detecter_comportements(df):
    """
    Analyse les logs par fenêtres de 15 minutes
    et détecte les comportements suspects et normaux.
    Retourne la liste de TOUTES les sessions (normal + suspect).
    """
    if df.empty:
        return []

    df['fenetre'] = df['time'].dt.floor('15min')
    resultats     = []

    for (machine, fenetre), groupe in df.groupby(['machine','fenetre']):
        heure = fenetre.hour

        # Compter les Event IDs de cette fenêtre
        ev = {
            4624: (groupe.event_id == 4624).sum(),  # connexion reussie
            4625: (groupe.event_id == 4625).sum(),  # echec connexion
            4634: (groupe.event_id == 4634).sum(),  # deconnexion
            4672: (groupe.event_id == 4672).sum(),  # privileges eleves
            4720: (groupe.event_id == 4720).sum(),  # compte cree
            4726: (groupe.event_id == 4726).sum(),  # compte supprime
            4798: (groupe.event_id == 4798).sum(),  # enum groupes user
            4799: (groupe.event_id == 4799).sum(),  # enum membres groupe
            5379: (groupe.event_id == 5379).sum(),  # lecture credentials
            5382: (groupe.event_id == 5382).sum(),  # lecture credentials
            4616: (groupe.event_id == 4616).sum(),  # changement heure
            4648: (groupe.event_id == 4648).sum(),  # credentials explicites
        }

        hors = 1 if (heure < 6 or heure >= 22) else 0
        nb_enum  = ev[4798] + ev[4799]
        nb_creds = ev[5379] + ev[5382]

        # ── Détecter les comportements suspects ──────────────
        comportements_detectes = []

        # BRUTEFORCE : 5+ échecs en 15 min
        if ev[4625] >= 5:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "BRUTEFORCE",
                **CVE_MAP["BRUTEFORCE"]
            })

        # ESCALADE PRIVILEGES : beaucoup de 4672 + hors horaires
        if ev[4672] >= 10 and hors == 1:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "ESCALADE_PRIVILEGES",
                **CVE_MAP["ESCALADE_PRIVILEGES"]
            })

        # CREATION COMPTE
        if ev[4720] >= 1:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "CREATION_COMPTE",
                **CVE_MAP["CREATION_COMPTE"]
            })

        # ENUMERATION COMPTES : 4798/4799 intensif
        if nb_enum >= 20:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "ENUMERATION_COMPTES",
                **CVE_MAP["ENUMERATION_COMPTES"]
            })

        # LECTURE CREDENTIALS : 5379/5382
        if nb_creds >= 5:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "LECTURE_CREDENTIALS",
                **CVE_MAP["LECTURE_CREDENTIALS"]
            })

        # CONNEXION NOCTURNE : connexion réussie la nuit
        if ev[4624] >= 1 and hors == 1 and not comportements_detectes:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "CONNEXION_NOCTURNE",
                **CVE_MAP["CONNEXION_NOCTURNE"]
            })

        # NORMAL : aucun comportement suspect détecté
        if not comportements_detectes:
            resultats.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "NORMAL",
                "cve": "N/A", "cvss": 0.0, "epss": 0.0,
                "desc": "Activite normale"
            })
        else:
            resultats.extend(comportements_detectes)

    suspects = [r for r in resultats if r['comportement'] != 'NORMAL']
    normaux  = [r for r in resultats if r['comportement'] == 'NORMAL']
    print(f"[PARSER] {len(resultats)} sessions : "
          f"{len(normaux)} normales + {len(suspects)} suspectes")
    return resultats


def _base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, total):
    """Retourne le dictionnaire de features de base d'une session."""
    return {
        "machine"         : machine,
        "fenetre"         : str(fenetre),
        "heure"           : int(heure),
        "nb_echecs"       : int(ev[4625]),
        "nb_succes"       : int(ev[4624]),
        "nb_ip_dist"      : 1,
        "privilege_eleve" : int(ev[4672]),
        "nb_powershell"   : 0,
        "nb_comptes_crees": int(ev[4720]),
        "nb_processus"    : int(ev[4648]),
        "hors_horaires"   : int(hors),
        "nb_total_events" : int(total),
        "nb_enum"         : int(nb_enum),
        "nb_creds"        : int(nb_creds),
    }


def stats_generales(df):
    """Retourne les statistiques générales du fichier de logs."""
    return {
        "total_events" : len(df),
        "machines"     : df['machine'].nunique() if 'machine' in df.columns else 1,
        "periode_debut": str(df['time'].min()),
        "periode_fin"  : str(df['time'].max()),
        "echecs_total" : (df.event_id == 4625).sum(),
        "connexions_ok": (df.event_id == 4624).sum(),
        "privileges"   : (df.event_id == 4672).sum(),
        "comptes_crees": (df.event_id == 4720).sum(),
        "enum_comptes" : ((df.event_id == 4798) | (df.event_id == 4799)).sum(),
        "lecture_creds": ((df.event_id == 5379) | (df.event_id == 5382)).sum(),
    }
