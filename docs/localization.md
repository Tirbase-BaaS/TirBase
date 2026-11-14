# Localization (F-15)

## Console (React) — current framework

- **Location:** `console/src/i18n.ts`
- **Mechanism:** typed `Locale`, `messages` map of `MessageKey` → string, `translate(locale, key, vars)`, React context (`I18nContext`) and `useI18n()`.
- **Supported locales (code):** `en` (English), `es` (Español) — **Spanish is the first non-English locale** shipped in the console.
- **Adding a new locale:**
  1. Add the locale code to the `Locale` union and to `locales` array in `console/src/i18n.ts`.
  2. Add a full message entry in `messages` for every `MessageKey` (TypeScript will enforce keys via the `satisfies`/shape pattern used).
  3. Verify formatting helpers that take `locale` (`Intl.*`) behave as expected.
  4. Add screenshots/QA notes if UI layout changes (text expansion).

## Gateway / CLI / API errors

- Many error strings are currently English and part of stable API contracts in some cases; changing them requires compatibility review. Prefer **error codes** in machine interfaces and localize human-facing text in clients (console) where possible.

## Documentation localization

- Core docs are English-first. Translations should be maintained under a clear policy (version pinning) to avoid drift; track translated doc sets in `docs/` subfolders (e.g. `docs/i18n/es/`) if introduced.

## Testing

- Smoke-test locale switching in the console (Settings / header language selector).
- Include at least one non-English locale in manual QA for each release that changes user-facing strings.
