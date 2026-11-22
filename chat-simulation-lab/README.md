# Chat Simulation Lab V4 — Android TEST

Offline, clearly labeled chat simulator. Android 8+ (API 26); independent package ID `app.chatsimulation.lab.v4` so it installs alongside the earlier TEST app without signature conflict.

Features: WhatsApp exported TXT **local copy** import, fictional incoming/outgoing messages, date/time, search, edit, delete, JSON backup/restore. Persistent SIMULATED labels and warnings. No permissions for network, SMS, contacts or WhatsApp private storage. No actual WhatsApp data is bundled.

Build: JDK 17, Gradle 8.9 and Android SDK Platform 35. Run from project directory: `gradle :app:assembleDebug`. Debug APK is for testing only. Original WhatsApp database not accessed or changed.
