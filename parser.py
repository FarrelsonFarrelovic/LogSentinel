import pandas as pd
from io import StringIO

# ─────────────────────────────────────────────────────────────
# TABLE CVE — comportement → CVE associée
# ─────────────────────────────────────────────────────────────
CVE_MAP = {
    "BRUTEFORCE"          : {"cve":"CVE-2019-0708",  "cvss":9.8,  "epss":0.97, "desc":"Windows RDP / SSH Brute Force"},
    "ESCALADE_PRIVILEGES" : {"cve":"CVE-2021-34527", "cvss":8.8,  "epss":0.95, "desc":"PrintNightmare - Escalade privileges"},
    "CONNEXION_NOCTURNE"  : {"cve":"CVE-2023-23397", "cvss":9.8,  "epss":0.88, "desc":"Connexion suspecte hors horaires"},
    "CREATION_COMPTE"     : {"cve":"CVE-2020-1472",  "cvss":10.0, "epss":0.96, "desc":"Zerologon - Creation compte suspect"},
    "ENUMERATION_COMPTES" : {"cve":"CVE-2021-36934", "cvss":7.8,  "epss":0.75, "desc":"Windows SAM - Enumeration comptes"},
    "LECTURE_CREDENTIALS" : {"cve":"CVE-2022-26925", "cvss":8.1,  "epss":0.82, "desc":"Windows LSA - Vol de credentials"},
    "ACTIVITE_NOCTURNE"   : {"cve":"CVE-2023-23397", "cvss":9.8,  "epss":0.88, "desc":"Activite suspecte hors horaires"},
}

# ─────────────────────────────────────────────────────────────
# MAPPING WAZUH RULE IDs → Event IDs Windows équivalents
# ─────────────────────────────────────────────────────────────
WAZUH_TO_EVENTID = {
    # Authentification réussie
    5715 : 4624,   # sshd: authentication success
    5501 : 4624,   # PAM: Login session opened
    # Authentification échouée
    5710 : 4625,   # sshd: authentication failed
    5503 : 4625,   # PAM: Login error
    # Sudo / élévation de privilèges
    5402 : 4672,   # sudo to ROOT executed
    5403 : 4672,   # sudo: command not allowed
    # Création/modification de compte
    5901 : 4720,   # useradd: new account added
    5902 : 4720,   # usermod: account modified
    5400 : 4720,   # PAM: new account created
    # Fermeture de session
    5502 : 4634,   # PAM: Login session closed
    # ── 3 Rule IDs manquants ajoutés ──────────────────────────
    # Surveillance réseau / ports
    533  : 4648,   # Listened ports status changed → auth réseau explicite
    # Audit SELinux — vérification de permission système
    80730: 4672,   # Auditd: SELinux permission check → privilege check
    # CIS Benchmark — alertes de conformité (niveau informatif, non intrusif)
    # On les mappe sur 4616 (changement heure système) = event neutre
    # pour qu'ils soient comptés mais n'alimentent aucun comportement suspect
    19004: 4616,   # SCA summary: score CIS < 50%
    19014: 4616,   # CIS: sticky bit not set (failed)
    19015: 4616,   # CIS: sudo installed (passed)
}

# ─────────────────────────────────────────────────────────────
# LECTURE ROBUSTE DU CSV
# ─────────────────────────────────────────────────────────────
def _lire_csv(source):
    tentatives = [
        dict(encoding='utf-8',     engine='python', on_bad_lines='skip'),
        dict(encoding='utf-8-sig', engine='python', on_bad_lines='skip'),
        dict(encoding='latin-1',   engine='python', on_bad_lines='skip'),
        dict(encoding='cp1252',    engine='python', on_bad_lines='skip'),
    ]
    last_err = None
    for opts in tentatives:
        try:
            if hasattr(source, 'seek'):
                source.seek(0)
            return pd.read_csv(source, **opts)
        except Exception as e:
            last_err = e
    raise ValueError(f"Impossible de lire le fichier CSV : {last_err}")


# ─────────────────────────────────────────────────────────────
# DETECTION FORMAT
# ─────────────────────────────────────────────────────────────
def _detecter_format(df):
    """
    Retourne (format, df_corrige).
    Formats : 'windows_standard' | 'windows_fr' | 'wazuh' | 'inconnu'
    """
    cols_norm = [c.strip().lower().replace(' ', '_') for c in df.columns]

    # ── Wazuh SIEM ────────────────────────────────────────────
    if 'timestamp' in cols_norm and 'rule_id' in cols_norm:
        return 'wazuh', df
    if 'rule_id' in cols_norm or 'agent_id' in cols_norm:
        return 'wazuh', df

    # ── Windows standard (PowerShell / export script) ─────────
    if any(c in cols_norm for c in ['timecreated', 'time_created', 'horodatage']):
        return 'windows_standard', df
    if 'id' in cols_norm and any(c in cols_norm for c in ['machinename', 'machine_name']):
        return 'windows_standard', df

    # ── Event Viewer FR — colonnes décalées ───────────────────
    # La colonne 0 contient en réalité la date (décalage d'une colonne)
    try:
        val0 = str(df.iloc[0, 0])
        pd.to_datetime(val0, dayfirst=True)
        df_fr = df.copy()
        df_fr.columns = (
            ['time', 'machine', 'event_id', 'categorie', 'message']
            + list(df.columns[5:])
        )
        return 'windows_fr', df_fr
    except Exception:
        pass

    # ── Event Viewer FR — colonnes lisibles ───────────────────
    if 'date_et_heure' in cols_norm:
        return 'windows_fr', df

    return 'inconnu', df


# ─────────────────────────────────────────────────────────────
# PARSER PRINCIPAL
# ─────────────────────────────────────────────────────────────
def parser_logs(source):
    """
    Lit un fichier CSV de logs.
    Supporte :
      - Windows PowerShell / standard  (TimeCreated, Id, MachineName, Message)
      - Windows Event Viewer FR        (Mots clés, Date et heure, Source, ID...)
      - Wazuh SIEM Linux               (Timestamp, Agent_ID, Rule_ID, Description, Level)
    """
    df = _lire_csv(source)

    fmt, df = _detecter_format(df)
    print(f"[PARSER] Format detecte : {fmt.upper()}")

    # Normaliser les noms de colonnes APRÈS correction décalage
    df.columns = [c.strip().lower().replace(' ', '_') for c in df.columns]

    # ── Rename selon le format ───────────────────────────────
    if fmt == 'windows_standard':
        rename_map = {
            'timecreated' : 'time', 'time_created': 'time',
            'date'        : 'time', 'horodatage'  : 'time',
            'id'          : 'event_id', 'eventid'  : 'event_id',
            'machinename' : 'machine',  'machine_name': 'machine',
            'ordinateur'  : 'machine',
            'username'    : 'user',     'user_name' : 'user',
            'ipaddress'   : 'ip',       'ip_address': 'ip',
            'message'     : 'message',
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    elif fmt == 'windows_fr':
        # Après correction décalage les colonnes sont déjà nommées
        # On fait un rename de sécurité pour les variantes
        rename_map = {'date_et_heure': 'time', 'source': 'machine'}
        for col in df.columns:
            if col not in ('time', 'machine', 'message', 'categorie') and 'id' in col:
                rename_map[col] = 'event_id'
                break
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    elif fmt == 'wazuh':
        rename_map = {
            'timestamp'  : 'time',
            'agent_name' : 'machine',
            'agent_id'   : 'agent_id',
            'rule_id'    : 'event_id',
            'description': 'message',
            'level'      : 'wazuh_level',
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    else:
        # Générique — recherche par mots-clés
        for col in df.columns:
            if any(k in col for k in ['time','date','heure','horod','timestamp']):
                df = df.rename(columns={col: 'time'}); break
        for col in df.columns:
            if any(k in col for k in ['id','event','rule','evenement']):
                df = df.rename(columns={col: 'event_id'}); break
        for col in df.columns:
            if any(k in col for k in ['machine','host','computer','agent','source']):
                df = df.rename(columns={col: 'machine'}); break

    # ── Valeurs par défaut ───────────────────────────────────
    if 'machine' not in df.columns:
        df['machine'] = 'MACHINE_INCONNUE'
    for col in ['user', 'ip', 'message']:
        if col not in df.columns:
            df[col] = ''

    # ── Vérifications obligatoires ───────────────────────────
    if 'time' not in df.columns:
        raise KeyError(
            f"Colonne 'time' introuvable.\n"
            f"Colonnes présentes : {', '.join(df.columns.tolist())}\n"
            f"Formats supportés : Windows PowerShell, Event Viewer FR, Wazuh SIEM"
        )
    if 'event_id' not in df.columns:
        raise KeyError(
            f"Colonne 'event_id' introuvable.\n"
            f"Colonnes présentes : {', '.join(df.columns.tolist())}"
        )

    # ── Conversion des types ─────────────────────────────────
    df['time']     = pd.to_datetime(df['time'], dayfirst=True, errors='coerce')
    df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(0).astype(int)
    df             = df.dropna(subset=['time']).sort_values('time').reset_index(drop=True)

    # ── Wazuh : Rule IDs → Event IDs Windows ─────────────────
    if fmt == 'wazuh':
        df['event_id'] = df['event_id'].map(
            lambda rid: WAZUH_TO_EVENTID.get(rid, rid)
        )
        print(f"[PARSER] Wazuh Rule IDs convertis en Event IDs Windows")

    print(f"[PARSER] {len(df)} evenements charges")
    if len(df) > 0:
        print(f"[PARSER] Periode  : {df['time'].min()} → {df['time'].max()}")
        print(f"[PARSER] Event IDs: {sorted(df['event_id'].unique())}")
    else:
        print("[PARSER] ATTENTION : aucun evenement valide lu")
    return df


# ─────────────────────────────────────────────────────────────
# DETECTION COMPORTEMENTS
# ─────────────────────────────────────────────────────────────
def detecter_comportements(df):
    if df.empty:
        return []

    df['fenetre'] = df['time'].dt.floor('15min')
    resultats     = []

    for (machine, fenetre), groupe in df.groupby(['machine', 'fenetre']):
        heure = fenetre.hour

        ev = {
            4624: (groupe.event_id == 4624).sum(),
            4625: (groupe.event_id == 4625).sum(),
            4634: (groupe.event_id == 4634).sum(),
            4672: (groupe.event_id == 4672).sum(),
            4720: (groupe.event_id == 4720).sum(),
            4726: (groupe.event_id == 4726).sum(),
            4798: (groupe.event_id == 4798).sum(),
            4799: (groupe.event_id == 4799).sum(),
            5379: (groupe.event_id == 5379).sum(),
            5382: (groupe.event_id == 5382).sum(),
            4616: (groupe.event_id == 4616).sum(),
            4648: (groupe.event_id == 4648).sum(),
        }

        hors     = 1 if (heure < 6 or heure >= 22) else 0
        nb_enum  = ev[4798] + ev[4799]
        nb_creds = ev[5379] + ev[5382]

        comportements_detectes = []

        if ev[4625] >= 5:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "BRUTEFORCE", **CVE_MAP["BRUTEFORCE"]
            })
        if ev[4672] >= 10 and hors == 1:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "ESCALADE_PRIVILEGES", **CVE_MAP["ESCALADE_PRIVILEGES"]
            })
        if ev[4720] >= 1:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "CREATION_COMPTE", **CVE_MAP["CREATION_COMPTE"]
            })
        if nb_enum >= 20:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "ENUMERATION_COMPTES", **CVE_MAP["ENUMERATION_COMPTES"]
            })
        if nb_creds >= 5:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "LECTURE_CREDENTIALS", **CVE_MAP["LECTURE_CREDENTIALS"]
            })
        if ev[4624] >= 1 and hors == 1 and not comportements_detectes:
            comportements_detectes.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "CONNEXION_NOCTURNE", **CVE_MAP["CONNEXION_NOCTURNE"]
            })

        if not comportements_detectes:
            resultats.append({
                **_base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, len(groupe)),
                "comportement": "NORMAL",
                "cve": "N/A", "cvss": 0.0, "epss": 0.0, "desc": "Activite normale"
            })
        else:
            resultats.extend(comportements_detectes)

    suspects = [r for r in resultats if r['comportement'] != 'NORMAL']
    normaux  = [r for r in resultats if r['comportement'] == 'NORMAL']
    print(f"[PARSER] {len(resultats)} sessions : {len(normaux)} normales + {len(suspects)} suspectes")
    return resultats


def _base(machine, fenetre, heure, ev, nb_enum, nb_creds, hors, total):
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
    return {
        "total_events" : len(df),
        "machines"     : df['machine'].nunique() if 'machine' in df.columns else 1,
        "periode_debut": str(df['time'].min()),
        "periode_fin"  : str(df['time'].max()),
        "echecs_total" : int((df.event_id == 4625).sum()),
        "connexions_ok": int((df.event_id == 4624).sum()),
        "privileges"   : int((df.event_id == 4672).sum()),
        "comptes_crees": int((df.event_id == 4720).sum()),
        "enum_comptes" : int(((df.event_id == 4798) | (df.event_id == 4799)).sum()),
        "lecture_creds": int(((df.event_id == 5379) | (df.event_id == 5382)).sum()),
    }
