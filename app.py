import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os, sys
from io import StringIO
from datetime import datetime, timedelta
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser   import parser_logs, detecter_comportements, stats_generales
from features import charger_modele, predire, NIVEAUX

# ─────────────────────────────────────────────────────────────
# CONFIG PAGE
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LogSentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
html,body,[class*="css"]{font-family:'IBM Plex Sans',sans-serif;background:#0d1117;color:#e6edf3;}
.block-container{padding:1.5rem 2.5rem;max-width:1400px;}
.header{border-bottom:1px solid #21262d;padding-bottom:1.2rem;margin-bottom:1.5rem;}
.header-title{font-family:'IBM Plex Mono',monospace;font-size:1.6rem;font-weight:700;color:#58a6ff;letter-spacing:-0.5px;}
.header-sub{font-size:0.82rem;color:#8b949e;margin-top:0.3rem;}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.2rem 1.4rem;margin-bottom:1.2rem;}
.card-title{font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#58a6ff;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #21262d;padding-bottom:0.5rem;margin-bottom:0.8rem;}
.stat-box{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:0.8rem;text-align:center;}
.stat-val{font-family:'IBM Plex Mono',monospace;font-size:1.6rem;font-weight:700;color:#58a6ff;}
.stat-lbl{font-size:0.72rem;color:#8b949e;margin-top:0.2rem;}
.alerte-row{background:#161b22;border:1px solid #21262d;border-left:4px solid;border-radius:8px;padding:1rem 1.2rem;margin-bottom:0.8rem;}
.alerte-titre{font-family:'IBM Plex Mono',monospace;font-size:0.9rem;font-weight:700;}
.alerte-meta{font-size:0.78rem;color:#8b949e;margin-top:0.3rem;}
.badge{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:0.75rem;font-weight:700;padding:0.25rem 0.7rem;border-radius:4px;letter-spacing:1px;}
.badge-CRITIQUE{background:rgba(248,81,73,0.15);color:#f85149;border:1px solid #f85149;}
.badge-ELEVE{background:rgba(210,153,34,0.15);color:#d29922;border:1px solid #d29922;}
.badge-MODERE{background:rgba(227,179,65,0.15);color:#e3b341;border:1px solid #e3b341;}
.badge-FAIBLE{background:rgba(63,185,80,0.15);color:#3fb950;border:1px solid #3fb950;}
.score-big{font-family:'IBM Plex Mono',monospace;font-size:3rem;font-weight:700;line-height:1;}
.action-box{border-radius:6px;padding:0.7rem 0.9rem;font-size:0.82rem;margin-top:0.6rem;border-left:3px solid;}
.action-CRITIQUE{background:rgba(248,81,73,0.08);border-color:#f85149;color:#ffa198;}
.action-ELEVE{background:rgba(210,153,34,0.08);border-color:#d29922;color:#f0c26e;}
.action-MODERE{background:rgba(227,179,65,0.08);border-color:#e3b341;color:#f0d060;}
.action-FAIBLE{background:rgba(63,185,80,0.08);border-color:#3fb950;color:#7ee787;}
.stButton>button{background:#238636!important;color:white!important;border:1px solid #2ea043!important;border-radius:6px!important;font-family:'IBM Plex Mono',monospace!important;font-size:0.85rem!important;font-weight:600!important;padding:0.5rem 1.5rem!important;width:100%!important;}
.stButton>button:hover{background:#2ea043!important;}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# CHARGEMENT MODELE
# ─────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    return charger_modele()

try:
    model = load_model()
    modele_ok = True
except FileNotFoundError:
    modele_ok = False

ACTIONS = {
    'CRITIQUE': 'Isoler immediatement la machine du reseau. Contacter le responsable securite. Lancer une investigation forensique.',
    'ELEVE'   : 'Alerter le responsable IT sous 1 heure. Surveiller activement les logs suivants.',
    'MODERE'  : 'Surveiller les prochaines activites. Verifier les comptes utilisateurs actifs.',
    'FAIBLE'  : 'Aucune action immediate. Consigner dans le rapport mensuel.',
}

ICONS = {
    'BRUTEFORCE'          : '🔨',
    'ESCALADE_PRIVILEGES' : '⬆️',
    'CONNEXION_NOCTURNE'  : '🌙',
    'CREATION_COMPTE'     : '👤',
    'ENUMERATION_COMPTES' : '🔍',
    'LECTURE_CREDENTIALS' : '🔑',
    'ACTIVITE_NOCTURNE'   : '🌙',
    'NORMAL'              : '✅',
}

# ─────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="header">
  <div class="header-title">🛡️ LogSentinel</div>
  <div class="header-sub">
    Detection de comportements suspects par analyse de logs Windows &nbsp;·&nbsp;
    Machine Learning + XAI &nbsp;·&nbsp; Contexte camerounais
  </div>
</div>
""", unsafe_allow_html=True)

# Avertissement si modèle absent
if not modele_ok:
    st.error("⚠️ model_logs.pkl introuvable — Lance d'abord : `python train.py`")
    st.stop()

# ─────────────────────────────────────────────────────────────
# LAYOUT
# ─────────────────────────────────────────────────────────────
col_left, col_right = st.columns([1, 1.6], gap="large")

with col_left:
    st.markdown('<div class="card"><div class="card-title">📂 Charger un fichier de logs</div>', unsafe_allow_html=True)
    fichier  = st.file_uploader(
        "Fichier CSV exporté depuis PowerShell ou Event Viewer",
        type=['csv','txt'],
        label_visibility='visible'
    )
    analyser = st.button("🔍 ANALYSER LES LOGS", use_container_width=True)
    st.markdown("""
    <div style='margin-top:0.8rem;padding:0.8rem;background:#0d1117;border:1px solid #21262d;border-radius:6px;font-size:0.75rem;color:#8b949e;'>
    <b style='color:#58a6ff'>Format attendu :</b><br>
    TimeCreated, Id, MachineName, Message<br><br>
    <b style='color:#58a6ff'>Event IDs analysés :</b><br>
    4624 Connexion · 4625 Echec · 4672 Privilege<br>
    4720 Compte créé · 4798/4799 Enumeration<br>
    5379/5382 Credentials
    </div>
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card"><div class="card-title">🧪 Demo — Logs simulés</div>', unsafe_allow_html=True)
    if st.button("Charger un exemple de logs suspects", use_container_width=True):
        st.session_state['demo'] = True
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# FONCTION DEMO
# ─────────────────────────────────────────────────────────────
def generer_logs_demo():
    random.seed(42)
    base   = datetime(2026, 5, 26, 9, 0, 0)
    lignes = ['TimeCreated,Id,MachineName,Message']

    def add(eid, delta, msg):
        nonlocal base
        base = base + timedelta(seconds=delta)
        lignes.append(f"{base.strftime('%d/%m/%Y %H:%M:%S')},{eid},MINFIN-SRV01,{msg}")

    # Comportement normal matin
    for _ in range(30):
        add(4624, random.randint(60,300), "An account was successfully logged on.")
        add(4672, random.randint(1,10),   "Special privileges assigned to new logon.")

    # Enumération comptes (10h)
    base = base.replace(hour=10, minute=0)
    for _ in range(50):
        add(4798, random.randint(1,5), "A query was made to a users local group membership.")
    for _ in range(20):
        add(5379, random.randint(1,3), "Credential Manager credentials were read.")

    # Bruteforce + création compte (22h)
    base = base.replace(hour=22, minute=0) + timedelta(days=0)
    for _ in range(20):
        add(4625, random.randint(1,4), "An account failed to log on.")
    add(4672, 2, "Special privileges assigned to new logon.")
    add(4672, 1, "Special privileges assigned to new logon.")
    add(4720, 3, "A user account was created.")
    add(4726, 30,"A user account was deleted.")

    return '\n'.join(lignes)

# ─────────────────────────────────────────────────────────────
# ANALYSE
# ─────────────────────────────────────────────────────────────
with col_right:

    demo_actif = st.session_state.get('demo', False)

    if (fichier and analyser) or demo_actif:

        # Charger les logs
        if demo_actif:
            csv_demo = generer_logs_demo()
            df_logs  = parser_logs(StringIO(csv_demo))
            st.session_state['demo'] = False
        else:
            df_logs = parser_logs(fichier)

        # Stats générales
        stats = stats_generales(df_logs)

        # Afficher stats
        cols_stat = st.columns(4)
        stat_items = [
            (stats['total_events'],  'Total événements'),
            (stats['echecs_total'],  'Echecs connexion'),
            (stats['machines'],      'Machines'),
            (stats.get('enum_comptes', 0) + stats.get('lecture_creds', 0), 'Enum + Credentials'),
        ]
        for i, (val, lbl) in enumerate(stat_items):
            with cols_stat[i]:
                st.markdown(f'<div class="stat-box"><div class="stat-val">{val}</div><div class="stat-lbl">{lbl}</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Détecter les comportements
        comportements = detecter_comportements(df_logs)

        # Séparer suspects et normaux
        suspects = [c for c in comportements if c['comportement'] != 'NORMAL']
        normaux  = [c for c in comportements if c['comportement'] == 'NORMAL']

        if not suspects:
            st.markdown("""
            <div class="card" style="text-align:center;padding:2rem;">
              <div style="font-size:2rem">✅</div>
              <div style="color:#3fb950;font-family:'IBM Plex Mono',monospace;font-weight:700;margin-top:0.5rem">
                AUCUN COMPORTEMENT SUSPECT DETECTE
              </div>
              <div style="color:#8b949e;font-size:0.82rem;margin-top:0.4rem">
                Les logs analysés ne présentent pas d'anomalie.
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Prédire pour chaque comportement suspect
            resultats = []
            for c in suspects:
                try:
                    pred = predire(c, model)
                    resultats.append({**c, **pred})
                except Exception as e:
                    st.warning(f"Erreur prédiction {c['comportement']}: {e}")

            # Trier par score décroissant
            resultats = sorted(resultats, key=lambda x: x['score'], reverse=True)

            # Résumé
            nb_crit  = sum(1 for r in resultats if r['niveau'] == 'CRITIQUE')
            nb_eleve = sum(1 for r in resultats if r['niveau'] == 'ELEVE')

            st.markdown(f"""
            <div style="display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
              <span style="background:rgba(248,81,73,0.1);border:1px solid #f85149;border-radius:6px;padding:0.3rem 0.8rem;font-size:0.8rem;color:#f85149;">
                🔴 {nb_crit} CRITIQUE(S)
              </span>
              <span style="background:rgba(210,153,34,0.1);border:1px solid #d29922;border-radius:6px;padding:0.3rem 0.8rem;font-size:0.8rem;color:#d29922;">
                🟠 {nb_eleve} ELEVÉ(S)
              </span>
              <span style="background:rgba(63,185,80,0.1);border:1px solid #3fb950;border-radius:6px;padding:0.3rem 0.8rem;font-size:0.8rem;color:#3fb950;">
                ✅ {len(normaux)} session(s) normale(s)
              </span>
              <span style="background:rgba(88,166,255,0.1);border:1px solid #58a6ff;border-radius:6px;padding:0.3rem 0.8rem;font-size:0.8rem;color:#58a6ff;">
                📋 {len(resultats)} alerte(s) total
              </span>
            </div>
            """, unsafe_allow_html=True)

            # Afficher chaque alerte
            for i, r in enumerate(resultats):
                niv   = r['niveau']
                col   = r['couleur']
                score = r['score']
                icon  = ICONS.get(r['comportement'], '⚠️')

                st.markdown(f"""
                <div class="alerte-row" style="border-left-color:{col}">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                    <div style="flex:1;">
                      <div class="alerte-titre" style="color:{col}">
                        {icon} {r['comportement'].replace('_',' ')}
                      </div>
                      <div class="alerte-meta">
                        Machine : <b>{r['machine']}</b> &nbsp;·&nbsp;
                        Fenêtre : {r['fenetre']} &nbsp;·&nbsp;
                        Heure : {r['heure']}h
                      </div>
                      <div class="alerte-meta">
                        CVE : <b>{r.get('cve','N/A')}</b> &nbsp;·&nbsp;
                        CVSS : {r.get('cvss',0)} &nbsp;·&nbsp;
                        EPSS : {r.get('epss',0)}
                      </div>
                      <div class="alerte-meta" style="color:#6e7681;font-size:0.73rem;">
                        {r.get('desc','')}
                      </div>
                    </div>
                    <div style="text-align:right;min-width:110px;margin-left:1rem;">
                      <div class="score-big" style="color:{col}">{score}</div>
                      <div style="font-size:0.7rem;color:#8b949e;">/100</div>
                      <span class="badge badge-{niv}">{niv}</span>
                    </div>
                  </div>
                  <div class="action-box action-{niv}">
                    <b>→ Action :</b> {ACTIONS[niv]}
                  </div>
                </div>
                """, unsafe_allow_html=True)

                # XAI — unique key par alerte
                with st.expander(f"🔬 Explication XAI — Alerte {i+1} : {r['comportement'].replace('_',' ')}"):

                    imp = r['importances']
                    fig_xai = go.Figure(go.Bar(
                        x=list(imp.values()),
                        y=list(imp.keys()),
                        orientation='h',
                        marker_color=[
                            '#f85149' if v >= sorted(imp.values())[-3] else '#58a6ff'
                            for v in imp.values()
                        ],
                        text=[f"{v:.1%}" for v in imp.values()],
                        textposition='outside',
                        textfont=dict(color='#8b949e', size=10)
                    ))
                    fig_xai.update_layout(
                        height=340, margin=dict(t=10,b=10,l=10,r=80),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                        yaxis=dict(tickfont=dict(color='#8b949e', size=10)),
                        showlegend=False
                    )
                    st.plotly_chart(
                        fig_xai,
                        use_container_width=True,
                        config={'displayModeBar': False},
                        key=f"xai_chart_{i}"
                    )

                    # Distribution probas
                    probas     = r['probas']
                    cols_p     = st.columns(4)
                    couleurs_p = {
                        'FAIBLE'  : '#3fb950',
                        'MODERE'  : '#e3b341',
                        'ELEVE'   : '#d29922',
                        'CRITIQUE': '#f85149'
                    }
                    for j, (nv, pv) in enumerate(probas.items()):
                        with cols_p[j]:
                            st.markdown(f"""
                            <div class="stat-box">
                              <div class="stat-val" style="color:{couleurs_p[nv]};font-size:1.3rem">{pv}%</div>
                              <div class="stat-lbl">{nv}</div>
                            </div>
                            """, unsafe_allow_html=True)

            # Export CSV
            st.markdown("<br>", unsafe_allow_html=True)
            df_export = pd.DataFrame([{
                'Comportement': r['comportement'],
                'Machine'     : r['machine'],
                'Fenetre'     : r['fenetre'],
                'Heure'       : r['heure'],
                'CVE'         : r.get('cve','N/A'),
                'CVSS'        : r.get('cvss', 0),
                'EPSS'        : r.get('epss', 0),
                'Score_ML'    : r['score'],
                'Niveau'      : r['niveau'],
                'Action'      : ACTIONS[r['niveau']],
            } for r in resultats])

            st.download_button(
                label     = "⬇️ Exporter le rapport complet (CSV)",
                data      = df_export.to_csv(index=False).encode('utf-8'),
                file_name = f"rapport_logsentinel_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime      = "text/csv",
                use_container_width=True,
                key="export_csv"
            )

    else:
        # Etat initial
        st.markdown("""
        <div style="height:420px;display:flex;flex-direction:column;
          align-items:center;justify-content:center;
          background:#161b22;border:1px dashed #30363d;
          border-radius:12px;text-align:center;">
          <div style="font-size:3rem;margin-bottom:1rem">🛡️</div>
          <div style="font-family:'IBM Plex Mono',monospace;color:#58a6ff;
               font-size:0.85rem;letter-spacing:2px;">EN ATTENTE DE LOGS</div>
          <div style="color:#8b949e;font-size:0.8rem;margin-top:0.8rem;
               max-width:300px;line-height:1.6;">
            Chargez un fichier de logs Windows CSV<br>
            ou utilisez la <b style='color:#58a6ff'>demo</b> pour tester
          </div>
          <div style="margin-top:1.5rem;display:flex;flex-wrap:wrap;
               justify-content:center;gap:0.4rem;max-width:360px;">
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">Bruteforce</span>
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">Escalade privileges</span>
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">Enumeration comptes</span>
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">Lecture credentials</span>
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">Score 0-100</span>
            <span style="background:#1c2128;border:1px solid #30363d;border-radius:20px;padding:0.2rem 0.6rem;font-size:0.68rem;color:#8b949e">XAI explicatif</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align:center;color:#8b949e;font-size:0.72rem;padding:0.3rem 0">
  LogSentinel 
</div>
""", unsafe_allow_html=True)
