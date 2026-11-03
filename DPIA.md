DPIA SMVogter v3.7 $0 Build
Legal basis: Art 6(1)(f) legitimate interest, Art 6(1)(b) contract for alerting
Data flow: Mic/simulated logs -> local AI Whisper.cpp pattern -> DaBERT local -> MQTT TLS 8883 -> no cloud
Retention: Audio 0s (never stored), transcript 7d encrypted, audit 2y hash-chain in SQLite, nonce 7d
Risk: Re-identification low (anonymize CPR/KONTO), impact medium, mitigation AES vault + TLS + anonymization
Revocation: mosquitto_passwd -D sonia, KID rotation 1->2 via .env.enc re-encrypt
