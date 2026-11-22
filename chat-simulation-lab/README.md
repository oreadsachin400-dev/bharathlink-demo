# Chat Simulation Lab Android TEST

Offline, clearly labeled chat simulation for Android. This app is not WhatsApp and cannot modify original WhatsApp chats or databases.

Features: exported TXT import, simulated incoming/outgoing messages with date and time, JSON backup and restore, local storage. No INTERNET, SMS, contacts, or storage-wide permission.

Build with JDK 17, Gradle 8.9, Android SDK Platform 35:
`gradle --no-daemon :app:assembleDebug`

APK output: `app/build/outputs/apk/debug/app-debug.apk`

Personal chat data or exported transcripts are never included in source or APK. Only generic sample text ships with the app. Back up the local simulation before clearing storage or uninstalling. APK is debug signed for testing and not intended for release.
