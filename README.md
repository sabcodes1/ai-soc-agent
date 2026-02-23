# AI SOC Agent

An on-premise AI agent that analyzes security alerts from Elastic SIEM 
using a local open source LLM — without sending any data outside the network.

## Problem
Security teams can't use cloud-based AI (ChatGPT, Claude) to analyze 
logs and alerts because log data contains sensitive information. 
This project solves that by running the model locally.

## How it works
1. Fetches alerts from Elasticsearch
2. Anonymizes sensitive fields (IPs, usernames, hostnames)
3. Sends to local LLM via Ollama
4. Returns structured analysis with severity, attack type, and recommended actions

## Stack
- Elastic SIEM — alert source
- Python — orchestration
- Ollama + Llama 3.1 8B — local inference
- FastAPI — dashboard (Phase 3)

## Status
🔧 Work in progress — Phase 1

## Roadmap
- [x] Ollama running locally
- [ ] Phase 1: Elastic → Python → LLM → terminal output
- [ ] Phase 2: Anonymization, correlation, structured output
- [ ] Phase 3: Dashboard, explainability, Docker deploy
