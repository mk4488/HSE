#!/usr/bin/env python
# coding: utf-8

# # Итоговое домашнее задание «Автоматизированный мониторинг и реагирование на угрозы»
# 
# ### Описание работы:
# 
# 1. **СБОР ДАННЫХ**:
# - API Vulners — для поиска уязвимостей;
# - логи Suricata — события сетевой безопасности.
# 2. **АНАЛИЗ ДАННЫХ**: критические уязвимости CVSS >= 7.0
# 3. **РЕАГИРОВАНИЕ НА УГРОЗЫ** (имитация): блокировка IP.
# 4. **ОТЧЁТ И ВИЗУАЛИЗАЦИЯ**.

# ## Импорт библиотек

import json
import os
import glob
import requests
import pandas as pd
import matplotlib.pyplot as plt

from dotenv import load_dotenv


# ##настройки

load_dotenv()  # загружает .env файл
LOGS_DIR = "release" # папка с логами
VULNERS_QUERY = "network intrusion"
BLOCK_THRESHOLD = 5 # порог блокировки IP
CVSS_CRIT = 7.0 # порог критичности CVE
REPORT = "report.csv"
CHART = "chart.png"


# ---
# ## 1. Сбор данных

# ### Логи Suricata
def load_logs(logs_dir=LOGS_DIR):
    """загружаем все eve.json из logs_dir"""
    log_files = glob.glob(os.path.join(logs_dir, "**", "eve.json"), recursive=True)
    events = []
    for filepath in log_files:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events

events = load_logs()


"""пример события"""
print(json.dumps(events[0], indent=2))

print(f'Пример IP из события, по которым будут искаться подозрительные адреса: {events[0]["src_ip"]}, в соотвествии с порогом')


# ### 1.2 API Vulners
def fetch_vulners_data(query=VULNERS_QUERY):
    """Запрашивает CVE через API Vulners."""
    api_key = os.getenv("VULNERS_API_KEY", "")
    if not api_key:
        return []

    try:
        resp = requests.post(
            "https://vulners.com/api/v3/search/lucene/",
            json={"query": query, "size": 20},
            headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
            timeout=15
        )
        data = resp.json()
        if data.get("result") == "OK":
            return [item.get("_source", item) for item in data["data"]["search"]]
    except Exception:
        pass

    return []


vulners_docs = fetch_vulners_data()



print(f"Пример бюллетеня безопасности: {json.dumps(vulners_docs[0], indent=2)}")


# ---
# ## Этап 2. Анализ данных
# ### 2.1 Анализ логов Suricata
df = pd.DataFrame(events)

# Типы событий
event_counts = df["event_type"].value_counts() if "event_type" in df.columns else pd.Series(dtype=int)
print("Типы событий:")
print(event_counts.to_string())



# Алерты
alerts_df = df[df["event_type"] == "alert"].copy() if "event_type" in df.columns else pd.DataFrame()


# Топ-10 Подозрительных источников
top_src = alerts_df["src_ip"].value_counts().head(10)
print("Топ-10 Подозрительных источников:")
print(top_src.to_string())



# Топ-10 сигнатур
if not alerts_df.empty:
    alerts_df["signature"] = alerts_df["alert"].apply(lambda x: x.get("signature", "unknown"))
    top_sigs = alerts_df["signature"].value_counts().head(10)
    print("Топ-10 сигнатур")
    print(top_sigs.to_string())


# ### 2.2 Анализ уязвимостей в API Vulners
def parse_vulners(documents):
    rows = []
    for doc in documents:
        score = doc.get("cvss", {})
        if isinstance(score, dict):
            score = score.get("score", 0)
        rows.append({
            "id": doc.get("id", "N/A"),
            "title": str(doc.get("title", "N/A"))[:80],
            "cvss_score": float(score or 0),
            "type": doc.get("type", "unknown")
        })
    return pd.DataFrame(rows).sort_values("cvss_score", ascending=False).reset_index(drop=True)


vuln_df = parse_vulners(vulners_docs)
critical_df = vuln_df[vuln_df["cvss_score"] >= CVSS_CRIT]
print(f"Всего уязвимостей: {len(vuln_df)}")
print(f"Из них критических, >= 7: {len(critical_df)}")


# ---
# ## Этап 3. Реагирование на угрозы
#Имитация
blocked = []

if not alerts_df.empty:
    ip_counts = alerts_df["src_ip"].value_counts()
    suspicious = ip_counts[ip_counts >= BLOCK_THRESHOLD]
    print(f"IP с >= 5 алертами ({len(suspicious)} шт.):")
    for ip, cnt in suspicious.items():
        print(f"  [БЛОКИРОВКА] {ip} — {cnt} событий")
        blocked.append({"ip": ip, "alert_count": int(cnt), "action": "blocked"})

print(f"Итого заблокировано: {len(blocked)}")

# ---
# ## Этап 4. Формирование отчёта и визуализация
# ### 4.1 Сохранение отчёта в CSV
report_rows = []

for item in blocked:
    report_rows.append({
        "source": "suricata", "id": item["ip"],
        "description": f"Заблокирован: {item['alert_count']} алертов",
        "severity": "high", "action": "blocked"
    })

for _, row in vuln_df.iterrows():
    score = row["cvss_score"]
    report_rows.append({
        "source": "vulners", "id": row["id"],
        "description": row["title"],
        "severity": "critical" if score >= 7.0 else "medium",
        "action": "patch" if score >= 7.0 else "review"
    })

report_df = pd.DataFrame(report_rows)
report_df.to_csv(REPORT, index=False, encoding="utf-8")
print(f"Отчёт сохранён с: {len(report_df)} записей")


# ### 4.2 Визуализация и сохранение графика
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle("Анализ угроз", fontsize=13, fontweight="bold")

# Топ-10 IP
top_ips = alerts_df["src_ip"].value_counts().head(10)
colors = ["#e74c3c" if v >= BLOCK_THRESHOLD else "#3498db" for v in top_ips.values]
ax1.barh(top_ips.index, top_ips.values, color=colors)
ax1.invert_yaxis()
ax1.set_xlabel("Количество событий")
ax1.set_title("Топ-10 подозрительных источников")

# CVSS
vs = vuln_df.sort_values("cvss_score")
colors2 = ["#e74c3c" if s >= 7.0 else "yellow" for s in vs["cvss_score"]]
ax2.barh(vs["id"].apply(lambda x: str(x)[:22]), vs["cvss_score"], color=colors2)
ax2.axvline(x=7.0, color="green", linestyle="--", alpha=0.6, label="Порог")
ax2.set_xlabel("CVSS")
ax2.set_title("Уязвимости CVSS")
ax2.legend(fontsize=8)

plt.tight_layout()
plt.savefig(CHART, dpi=150)
plt.show()
print(f"График сохранён: {CHART}")




