from elasticsearch import Elasticsearch
import ollama
import json

es = Elasticsearch(
    "http://localhost:9200",
    basic_auth=("elastic", "YnpX7UXzgCuUgw336uFg"),
    verify_certs=False
)

results = es.search(
    index=".ds-logs-windows.security*",
    query={"match": {"event.code": "4625"}},
    size=5,
    sort=[{"@timestamp": {"order": "desc"}}]
)

hits = results["hits"]["hits"]
print(f"Fant {len(hits)} failed login events\n")

for hit in hits:
    source = hit["_source"]
    event_data = source.get('winlog', {}).get('event_data', {})
    print("---")
    print(f"Tidspunkt:  {source.get('@timestamp', 'Ukjent')}")
    print(f"Bruker:     {event_data.get('TargetUserName', 'Ukjent')}")
    print(f"Kilde IP:   {event_data.get('IpAddress', 'Ukjent')}")
    print(f"Datamaskin: {source.get('winlog', {}).get('computer_name', 'Ukjent')}")
    print(f"Årsak:      {event_data.get('FailureReason', 'Ukjent')}")
    print()

# Analyser alle alerts i løkken
print("\n=== ANALYSERER ALLE ALERTS ===\n")

resultater = []

for hit in hits:
    source = hit["_source"]
    event_data = source.get('winlog', {}).get('event_data', {})
    
    prompt = f"""
Du er en SOC-analytiker. Analyser denne Windows-sikkerhetshendelsen.

Hendelse:
- Tidspunkt: {source.get('@timestamp')}
- Event ID: 4625 (Failed Login)
- Datamaskin: {source.get('winlog', {}).get('computer_name')}
- Kilde IP: {event_data.get('IpAddress')}
- Årsak: {event_data.get('FailureReason')}
- Status kode: {event_data.get('Status')}

Svar KUN med et JSON-objekt, ingen annen tekst:
{{
  "severity": "HIGH/MEDIUM/LOW",
  "attack_type": "type angrep her",
  "summary": "kort forklaring her",
  "confidence": 85,
  "actions": ["tiltak 1", "tiltak 2", "tiltak 3"]
}}
"""

    respons = ollama.chat(model="llama3.1:8b", messages=[
        {"role": "user", "content": prompt}
    ], options={"temperature": 0.1})

    try:
        analyse = json.loads(respons["message"]["content"])
        analyse["tidspunkt"] = source.get('@timestamp')
        analyse["ip"] = event_data.get('IpAddress')
        resultater.append(analyse)

        print(f"Tidspunkt: {analyse['tidspunkt']}")
        print(f"Severity:  {analyse['severity']}")
        print(f"Type:      {analyse['attack_type']}")
        print(f"Confidence:{analyse['confidence']}%")
        print()

    except json.JSONDecodeError:
        print(f"JSON-feil for hendelse {source.get('@timestamp')}")

# Korrelasjonslogikk
from collections import Counter
ip_count = Counter(r["ip"] for r in resultater)
high_count = sum(1 for r in resultater if r["severity"] == "HIGH")

print("=== KORRELASJON ===")
for ip, count in ip_count.items():
    if count >= 3:
        print(f"⚠️  {ip} har {count} failed logins — mulig brute force")

if high_count >= 3:
    print(f"\n🚨 {high_count} HIGH alerts — ESKALERER TIL ANALYTIKER")
elif high_count >= 1:
    print(f"\n⚠️  {high_count} HIGH alert — krever vurdering")
else:
    print("\n✅ Ingen kritiske alerts")
