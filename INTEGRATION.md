# Podpięcie panelu do auth — checklista end-to-end

Dotyczy każdego panelu: backend Symfony z `musikhood/auth-client-bundle` ≥ 0.8 i front
z `@musikhood-dev/auth-client` ≥ 2.3.1 (React Router 7 albo Vue 3), uwierzytelniane przez centralny auth server
(w przykładach `https://auth.example.com`) z panelem administracyjnym (panele, userzy, polityka 2FA).
Konkretne adresy i dane Twojej organizacji: dokument integracji w Work HUB
(`project_context_get(doc="AUTH_INTEGRATION.md")` w projekcie auth servera) i baza dostępów (`secret_to_env`).

Agent AI: zacznij od [AI_INTEGRATION.md](AI_INTEGRATION.md) (w paczce:
`vendor/musikhood/auth-client-bundle/AI_INTEGRATION.md`) — drzewo decyzji, przepisy scalania, pułapki.

Cel: integrator **nic nie konfiguruje** poza danymi panelu w env. Polityka 2FA i device binding żyją
wyłącznie w panelu administracyjnym auth servera.

| # | Kto | Co | Gotowe, gdy |
|---|---|---|---|
| [1](#1-admin-panel-w-panelu-administracyjnym) | admin | panel w panelu administracyjnym + dane w bazie dostępów Work HUB | jest `AUTH_BASE_URL`, `panel_id`, `client_id`, `client_secret` |
| [2](#2-backend-panelu) | dev | `composer require` → env → `auth-client:install` → `auth-client:doctor` | doctor zielony |
| [3](#3-front-panelu) | dev | `npm i` → `npx … init` → 2 linie w root | logowanie działa lokalnie |
| [4](#4-polityka-2fa-panelu) | admin | polityka 2FA panelu | user widzi to, czego oczekujemy |
| [5](#5-najczęstsze-problemy) | dev | gdy coś nie działa | — |

---

## 1. Admin: panel w panelu administracyjnym

W panelu administracyjnym auth servera → **Panele → „Dodaj panel”**:

| Pole | Wartość | Uwagi |
|---|---|---|
| Nazwa | np. `reports` | |
| Środowisko | `prod` / `dev` / `localhost` | osobny panel per środowisko |
| Origin | origin FRONTU, np. `https://reports.example.com` | albo `origin_pattern` (regex), np. dla `localhost:*` |
| Client ID | np. `reports` (małe litery, `-`, `_`) | włącza logowanie server-to-server (bundle) |
| Webhook URL | bazowy URL BACKENDU panelu, np. `https://reports-api.example.com` | auth server dokleja `/api/auth-client/webhook/user-invalidated` (0 s rewokacji) |
| Polityka 2FA | `off` na start | patrz [4](#4-polityka-2fa-panelu) |
| Device binding | wyłączone | włączać dopiero po pilotażu |

`client_secret` jest pokazywany **raz** (przy utworzeniu panelu / „Zregenerować client secret?”). Od razu zapisz
`panel_id`, `client_id`, `client_secret` w **bazie dostępów Work HUB** projektu (to jedyne źródło —
nigdzie indziej, nie w repo). Nadaj userom dostęp do panelu (role panelu bez prefiksu `ROLE_`).

> Bundle potrzebuje auth servera z endpointami `/api/auth/backend/*`. Jeśli Twoja instancja dev auth servera
> ich nie wystawia (np. lustro przekazujące tylko logowanie), panel dev też musi używać produkcyjnego — który
> adres wpisać, mówi dokument integracji organizacji.

## 2. Backend panelu

```bash
composer require musikhood/auth-client-bundle:^0.8
```

Dane panelu z bazy dostępów Work HUB — przez `secret_to_env` do `.env.local` (lokalnie) i do sekretu k8s
(dev/prod):

```dotenv
AUTH_PANEL_ID=…        # UUID panelu
AUTH_CLIENT_ID=…
AUTH_CLIENT_SECRET=…
AUTH_BASE_URL=…        # adres auth servera, np. https://auth.example.com (wymagany od 0.8.1)
# AUTH_COOKIE_DOMAIN — opcjonalnie; np. .example.com, gdy front i API są na różnych subdomenach
```

```bash
bin/console auth-client:install      # pokazuje zmiany i pyta; --dry-run tylko pokazuje
bin/console auth-client:doctor       # ma być zielono (! = ostrzeżenie, nie blokuje)
```

`install` dopisuje brakujące klucze do `.env`, import tras, `security.yaml` (własnych firewalli nie
nadpisuje — wypisze fragment), CORS (Nelmio) i trusted proxies. Szczegóły: [README → Komendy](README.md#komendy).

Encja `User`, tabela i migracje **nie są potrzebne** (tryb bezstanowy). Lokalna tabela userów — tylko
gdy aplikacja jej potrzebuje: [README → lokalna kopia](README.md#opcjonalnie-lokalna-kopia-userów-encja--tabela).

**Na dev/prod** (k8s): te same env w sekrecie + `SYMFONY_TRUSTED_PROXIES=private_ranges` (install dopisuje
do `.env`), `CORS_ALLOW_ORIGIN` = regex originu frontu. Po deployu:

```bash
kubectl exec deploy/<panel>-api -- bin/console auth-client:doctor
```

Pełna weryfikacja `panel_id` ↔ `client_id`: zaloguj się w przeglądarce, skopiuj wartość ciasteczka
`BEARER` i uruchom `bin/console auth-client:doctor --access-token=<BEARER>`.

## 3. Front panelu

```bash
npm i @musikhood-dev/auth-client@^2.3.1 @tanstack/react-query   # Vue: @tanstack/vue-query
npx @musikhood-dev/auth-client init                             # --dry-run: tylko plan
```

Wersja wprost — `latest` w npm to jeszcze 2.1.0 (bez `init` i 2FA). `init` wykrywa React Router 7 / Vue 3,
shadcn/ui i shadcn-vue, toast używany w kodzie, zmienną z adresem API (`--env-var`), istniejącą stronę `/login`
i istniejący `lib/auth.ts`; tworzy `lib/auth.ts`, `lib/mfa.ts`, komponenty 2FA i formularz / stronę logowania.
Istniejących plików nie nadpisuje (`--force`). Na końcu wypisuje brakujący kod do roota — dla React Router 7
(`app/root.tsx`, w `App()`):

```tsx
<AuthProvider client={authClient} navigate={(path) => navigate(path, { replace: true })}>
  <Outlet />
  <AuthMfaDialogs />
</AuthProvider>
```

Zmienna z adresem API (`VITE_API_BASE_URL` albo ta, której panel już używa) = URL backendu panelu (nie auth
servera). Front bez własnego backendu (loguje się wprost do auth servera) — wariant (b) w
[AI_INTEGRATION.md](AI_INTEGRATION.md#b-front-bezpośrednio-do-api-core-bez-własnego-backendu). Szczegóły:
[README auth-client](https://github.com/musikhood/auth-client#quick-start-5-minut).

## 4. Polityka 2FA panelu

Ustawiana per panel (pole „Polityka 2FA”). Zmiana działa od razu — bez deployu panelu.

| Polityka | User bez 2FA | User z 2FA |
|---|---|---|
| `off` (start) | loguje się hasłem | loguje się hasłem (bez kodu) |
| `optional` | loguje się hasłem | po haśle krok kodu (albo „zapamiętane urządzenie” 30 dni) |
| `required` | po haśle przekierowanie na konfigurację 2FA (`/setup-2fa`), potem logowanie z kodem | po haśle krok kodu |

- Sesja zalogowana przed zmianą na `optional`/`required` → przy najbliższym requeście (≤ 30 s) dialog
  „Potwierdź tożsamość” (step-up) albo „Ten panel wymaga 2FA” (hasło → konfiguracja). Alternatywa: „Wyloguj się”.
- **Kod zapasowy** loguje, ale nigdy nie zapamiętuje urządzenia — user powinien poprosić admina o ponowną
  konfigurację 2FA (reset w panelu administracyjnym: użytkownik → „Resetuj 2FA”).
- Klienci maszynowi z `X-Api-Token` omijają 2FA.
- Device binding: najpierw obserwacja (domyślny tryb), włączanie per panel dopiero po pilotażu.

## 5. Najczęstsze problemy

Zawsze zacznij od `bin/console auth-client:doctor` — każda pozycja ✘ ma podpowiedź.

### CORS
**Objaw:** w konsoli przeglądarki „blocked by CORS policy”, preflight `OPTIONS` bez
`Access-Control-Allow-Origin`; logowanie „nic nie robi”.
**Doctor:** `CORS (front na innym originie)` ✘ — `allow_credentials`, `X-Device-Fp`, `Retry-After`, pusty
`allow_origin`.
**Naprawa:** `auth-client:install` (uzupełni `nelmio_cors.yaml`), `CORS_ALLOW_ORIGIN` = regex originu
frontu na danym środowisku (np. `^https://reports\.example\.com$`).

### Cookie domain / ciasteczka nie wracają
**Objaw:** `/api/login` zwraca 200, ale następny request 401; w DevTools ciasteczka odrzucone
(„SameSite=None requires Secure”, „domain mismatch”).
**Doctor:** `Ciasteczka sesji` — `same_site=none` bez `secure` = ! (przeglądarka odrzuci ciasteczko);
`none` przy froncie w tej samej domenie = podpowiedź „lax wystarczy”; info o domenie.
**Naprawa:** front i API na różnych subdomenach tej samej domeny → `AUTH_COOKIE_DOMAIN=.example.com`
(`same_site` zostaje domyślne `lax` — SameSite liczy się po domenie rejestrowalnej, nie po hoście).
Front i API w **różnych domenach** → `auth_client.cookie.same_site: none` + HTTPS (`secure: true`).
Front musi wysyłać `withCredentials` (auth-client robi to sam).

### Trusted proxies / IP usera
**Objaw:** w historii logowań (panel administracyjny) IP ingressu albo brak IP; limit prób działa tylko per e-mail.
**Doctor:** `Trusted proxies` ! — brak.
**Naprawa:** `SYMFONY_TRUSTED_PROXIES=private_ranges` (install dopisuje). Auth server traktuje prywatne
`X-Client-Ip` jak brak nagłówka — na klastrze, gdzie prawdziwe IP ginie przed proxy (ingress), to bezpieczny
fallback (bez wspólnego limitu dla całego panelu).

### 403 panelowe
**Objaw:** po zalogowaniu 403 „brak dostępu do panelu”; front zostaje na `/login`, inne panele działają.
**Doctor:** wszystko zielone — to nie konfiguracja.
**Naprawa:** w panelu administracyjnym nadaj userowi dostęp do TEGO panelu; sprawdź, czy `AUTH_PANEL_ID` i
`AUTH_CLIENT_ID` są z tego samego panelu (`doctor --access-token=<BEARER>`). Dostęp i role propagują się
w ≤ 30 s, bez ponownego logowania.

### `mfa_step_up` / `mfa_enrollment_required`
**Objaw:** 403 z `code: mfa_step_up` albo `mfa_enrollment_required` na każdym requeście; dialog 2FA.
**Doctor:** `Trasy publiczne bundla` musi być ✔ — inaczej `/api/session/mfa` sam dostaje 403 i dialog
nie może się zakończyć.
**Naprawa:** to zamierzone przy polityce `optional`/`required` — user podaje kod / konfiguruje 2FA. Jeśli
dialog wisi mimo poprawnego kodu: sprawdź `security.yaml` (`auth-client:install --dry-run`) i wersję
auth-client (≥ 2.3.1 — reset stanu 2FA po wylogowaniu, dialogi poza `<AuthBoundary>`).

### Inne
- `Dane klienta` ✘ → zły `AUTH_CLIENT_SECRET` (zregeneruj secret w panelu administracyjnym i zaktualizuj bazę dostępów).
- `Auth server osiągalny` ✘ → `AUTH_BASE_URL` / DNS / ruch wychodzący z poda.
- `Auth server obsługuje 2FA` ✘ → zbyt stary auth server dla bundla ≥ 0.7.
