from elasticsearch import Elasticsearch
import ollama

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

# Send første hendelse til Ollama
first = hits[0]["_source"]
event_data = first.get('winlog', {}).get('event_data', {})

prompt = f"""
Du er en SOC-analytiker. Analyser denne Windows-sikkerhetshendelsen:

Tidspunkt: {first.get('@timestamp')}
Event ID: 4625 (Failed Login)
Datamaskin: {first.get('winlog', {}).get('computer_name')}
Kilde IP: {event_data.get('IpAddress')}
Årsak: {event_data.get('FailureReason')}
Status kode: {event_data.get('Status')}

Svar med:
- Severity: HIGH / MEDIUM / LOW
- Hva skjedde
- Anbefalt tiltak
"""

print("\n=== OLLAMA ANALYSE ===\n")
respons = ollama.chat(model="llama3.1:8b", messages=[
    {"role": "user", "content": prompt}
])
print(respons["message"]["content"])
