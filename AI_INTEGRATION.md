# Auth: podpięcie panelu — instrukcja dla agenta AI

Kanoniczna instrukcja integracji panelu z centralnym auth serverem. Napisana dla agenta AI: konkretne kroki,
decyzje, komendy i kryteria „gotowe”. Ludzka checklista: [INTEGRATION.md](INTEGRATION.md).
Wersja frontowa (skrót + przepisy dla frontu): `node_modules/@musikhood-dev/auth-client/AI_INTEGRATION.md`.

Wersje: bundle `musikhood/auth-client-bundle` **^0.8**, front `@musikhood-dev/auth-client` **^2.3.1**
(React Router 7 albo Vue 3). Auth server ma panel administracyjny (panele, userzy, polityka 2FA, tokeny API).

**Konkretne adresy i dane panelu Twojej organizacji:** dokument integracji w Work HUB
(`project_context_get(doc="AUTH_INTEGRATION.md")` w projekcie auth servera) i baza dostępów (`secret_to_env`).
Adresy w tym pliku (`https://auth.example.com`, `https://auth-dev.example.com`, `https://api.example.com`) to
tylko przykłady.

## Zasady dla agenta

- **Sekrety nigdy w kodzie, repo ani rozmowie.** `client_secret` i inne dane panelu bierz wyłącznie z bazy dostępów
  Work HUB narzędziem `secret_to_env` (zapisuje do `.env.local` / sekretu). Nie wypisuj wartości, nie wklejaj ich do
  commitów, logów ani raportu — co najwyżej nazwy zmiennych.
- **Bez commitów, pushy i deployu bez wyraźnej zgody operatora.** Merge do gałęzi deployu = wdrożenie.
- **Bez zmian w auth serverze i w paczkach** (bundle, auth-client) w ramach podpinania panelu — potrzebna zmiana
  (np. CORS auth servera) = notatka do raportu i pytanie do operatora.
- Polityka 2FA i device binding żyją **tylko w panelu administracyjnym auth servera** — nie konfiguruj ich w kodzie
  panelu.
- **Raport na końcu:** wariant (a/b/c), lista plików z jednym zdaniem, wynik `auth-client:doctor` (backend) albo
  `vue-tsc`/`tsc` + build (front), testy ręczne wykonane i do wykonania, otwarte punkty.

## Zanim zaczniesz — co musi dać człowiek / admin

1. **Rekord panelu w panelu administracyjnym** (Panele → „Dodaj panel”): nazwa, środowisko (`prod` / `dev` / `localhost` —
   osobny panel per środowisko), **Origin frontu** (albo regex `origin_pattern`, np. dla `localhost:*`), polityka
   2FA (`off` na start), device binding (wyłączone). Dla wariantu (a) także **Client ID** i **Webhook URL** = bazowy
   URL backendu panelu (auth server dokleja `/api/auth-client/webhook/user-invalidated`).
2. **Dane panelu w bazie dostępów Work HUB** projektu: adres auth servera (`AUTH_BASE_URL`), `panel_id` (UUID),
   `client_id`, `client_secret` (pokazywany w panelu administracyjnym raz). Ty ich nie generujesz i nie widzisz — używasz `secret_to_env`.
3. **Dostęp userów do panelu** nadany w panelu administracyjnym (role panelu bez prefiksu `ROLE_`).
4. Wariant (b): **Origin frontu w CORS auth servera** — zmiana po stronie auth servera, robi ją jego zespół.

Brakuje czegoś z listy → zatrzymaj się i poproś operatora; nie zgaduj wartości.

## Drzewo decyzji

```
Czy panel ma UI w przeglądarce?
├─ nie → (c) serwis maszynowy: X-Api-Token przez backend z bundlem
└─ tak → Czy panel ma (albo ma mieć) własny backend Symfony?
         ├─ tak → (a) backend z bundlem + front z auth-client (baseUrl = backend panelu)
         └─ nie → (b) front loguje się bezpośrednio do auth servera (baseUrl = auth server)
Nowy czy istniejący projekt? → nowy: generuj wszystko (init / install);
                               istniejący: --dry-run, potem przepisy scalania (niżej), nic nie nadpisuj (--force tylko
                               za zgodą operatora).
Panel ma już własne komponenty 2FA? → NIE uruchamiaj init; tylko podbij auth-client do ^2.3.1.
```

Który panel organizacji jest w którym wariancie i na jakiej wersji — dokument integracji w Work HUB.

## Co jest w paczkach

### Bundle `musikhood/auth-client-bundle` (Symfony 6.4 / 7, PHP ≥ 8.2)

- **Komendy:** `bin/console auth-client:install` (`--dry-run`, `--yes`/`-y`, `--no-doctor`) — dopisuje brakujące
  klucze do `.env`, `config/routes/auth_client.yaml`, `security.yaml` (pełny tylko gdy brak / domyślny; przy własnych
  firewallach wypisuje fragment), `nelmio_cors.yaml` (`allow_credentials`, `X-Device-Fp`, `Retry-After`),
  `framework.yaml` trusted proxies (Symfony < 7.2); pokazuje diff, pyta, idempotentny, na końcu doctor.
  `bin/console auth-client:doctor` (`--access-token=<BEARER>`) — ✔ / ! / ✘ z podpowiedziami, exit 1 przy ✘, bez
  sekretów: konfiguracja, format `panel_id`, `AUTH_BASE_URL`, JWKS, dane klienta, 2FA na serwerze, `panel_id` ↔
  klient (z tokenem), trasy publiczne w `security.yaml`, firewall `/api/v1/user/me`, CORS, ciasteczka, trusted proxies.
- **Env:** `AUTH_BASE_URL`, `AUTH_PANEL_ID`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET` (wymagane; od 0.8.1 bez wbudowanego
  adresu auth servera),
  `AUTH_COOKIE_DOMAIN` (puste = host-only), `SYMFONY_TRUSTED_PROXIES=private_ranges`, `CORS_ALLOW_ORIGIN` (Nelmio).
- **Trasy publiczne** (`Routing\PublicRoutes`): `POST /api/login`, `/api/login/mfa`, `/api/session/mfa`,
  `/api/mfa/enrollment/request`, `/api/token/refresh`, `/api/logout`, `/api/token/invalidate`,
  `/api/auth-client/webhook/user-invalidated`. Chroniona: `GET /api/v1/user/me`.
- **Uwierzytelnianie:** `JwtCookieAuthenticator` (ciasteczka `BEARER` 15 min + `refresh_token` 30 dni, HttpOnly,
  Secure, SameSite domyślnie `lax`), `ApiTokenAuthenticator` (`X-Api-Token: mhpat_…`), `AuthValidationListener`
  (co 30 s per user: sesja, dostęp do panelu, polityka 2FA → 403 `mfa_step_up` / `mfa_enrollment_required`).
- **Userzy:** domyślnie bezstanowo (bez encji i migracji). Własna tabela: encja `PanelUserInterface` + repozytorium
  `PanelUserRepositoryInterface` z `#[AsAlias]` (wzory: `docs/example-*.php|sql`).

### Front `@musikhood-dev/auth-client` (React 18/19, Vue 3.4+, TanStack Query 5)

- Core: `createAuthClient`, błędy (`InvalidCredentialsError`, `MfaRequiredError`, `MfaStepUpRequiredError`,
  `TooManyAttemptsError`, `PanelAccessDeniedError`, …) + `isAuthErrorNamed(err, 'Name')`.
- React (`/react`): `AuthProvider`, `AuthBoundary`, `useAuth`, `useMfa`. Vue (`/vue`): `createAuth`, `AuthBoundary`,
  `useAuth`, `useMfa`.
- CLI: `npx @musikhood-dev/auth-client init` (`--dry-run`, `--force`, `--env-var`, `--skip-format`, `--framework`).
- Eventy klienta: `login`, `logout`, `unauthorized`, `user-changed`, `panel-access-denied`, `forbidden`,
  `mfa-required`, `mfa-step-up-required`, `mfa-enrollment-required`, `mfa-state-changed`, `login-error`,
  `logout-error`, `refresh-error`.

### Kody błędów (auth server i bundle: `{"error": "<tekst>", "code": "<kod>"}`)

| HTTP | `code` | Znaczenie / reakcja frontu (auth-client robi to sam) |
|---|---|---|
| 401 | `invalid_credentials` | złe hasło — komunikat inline |
| 401 | `mfa_required` (+ `mfa_token`, `methods`) | krok kodu 2FA (`useMfa().stage === 'code'`) |
| 401 | `mfa_invalid_code` / `mfa_code_reused` | zły / ponownie użyty kod — inline |
| 401 | `mfa_token_expired` | wróć do hasła |
| 403 | `mfa_enrollment_required` (+ `enrollment_url` przy loginie) | konfiguracja 2FA (login: przekierowanie; w sesji: dialog z hasłem) |
| 403 | `mfa_step_up` | dialog „Potwierdź tożsamość” — sesja żyje, bez redirectu na login |
| 403 | `panel_access_denied` | brak dostępu do TEGO panelu (stan terminalny, sesja żyje) |
| 403 | `account_disabled` | konto wyłączone |
| 409 | `mfa_already_enabled` | 2FA już włączone |
| 429 | `too_many_attempts` (+ nagłówek `Retry-After`) | „spróbuj za N s” |
| 401 | `device_mismatch` (refresh) | sesja unieważniona — jak wygaśnięcie |
| 401 | `device_mismatch_recheck` | refresh + retry (paczka robi sama) |

## (a) Backend Symfony z bundlem + front

1. `composer require musikhood/auth-client-bundle:^0.8`
2. `secret_to_env` → `.env.local`: `AUTH_BASE_URL`, `AUTH_PANEL_ID`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`.
3. `bin/console auth-client:install --dry-run` → przejrzyj → `bin/console auth-client:install` (zgoda operatora na zapis
   przy istniejących plikach konfiguracji).
4. `bin/console auth-client:doctor` → **gotowe, gdy brak ✘** (! nie blokuje). Po zalogowaniu w przeglądarce pełne
   sprawdzenie: `bin/console auth-client:doctor --access-token=<BEARER>` (wartość ciasteczka podaje operator).
5. k8s (dev/prod): te same env w sekrecie + `SYMFONY_TRUSTED_PROXIES=private_ranges` + `CORS_ALLOW_ORIGIN` = regex
   originu frontu; po deployu `kubectl exec deploy/<panel>-api -- bin/console auth-client:doctor`.
6. Front — jak (b), ale `baseUrl` = **URL backendu panelu** (nie auth servera).

Uwaga: bundle wymaga endpointów `/api/auth/backend/*`. Instancja dev auth servera bez nich (np. lustro przekazujące
tylko logowanie) się nie nada — wtedy panel dev używa produkcyjnego auth servera (adres: dokument organizacji).

## (b) Front bezpośrednio do auth servera (bez własnego backendu)

1. Zmiana po stronie auth servera (operator / zespół auth servera): origin frontu w jego CORS (prod i dev). Rekord
   panelu w panelu administracyjnym z tym samym originem (bez niego panel nie ma polityki 2FA ani kontroli dostępu — 2FA `optional`).
2. Front: patrz [Front: kroki](#front-kroki-a-i-b). `baseUrl` = auth server, np. `https://auth.example.com`
   (dev: `https://auth-dev.example.com`).
3. **Gotowe, gdy:** `vue-tsc`/`tsc` + build przechodzą, a testy ręczne z listy niżej przechodzą na dev.

## (c) Serwis maszynowy (X-Api-Token, bez UI)

- Token `mhpat_…` tworzy **tylko admin** w panelu administracyjnym (per user i panel; `POST /api/v1/admin/users/{userId}/panels/{panelId}/api-token`).
  Trafia do bazy dostępów Work HUB → `secret_to_env` w serwisie wywołującym.
- Serwis wywołujący wysyła nagłówek `X-Api-Token: <token>` do **backendu z bundlem** (wariant a). Bundle weryfikuje
  token na żywo w auth serverze (fail-closed: auth server niedostępny = 401), sprawdza, że token należy do
  `AUTH_PANEL_ID`, role = role panelu z prefiksem `ROLE_`. **Omija 2FA.**
- Bez UI nie potrzebujesz auth-client ani CORS. Wywołania auth servera bezpośrednio tokenem `mhpat_` — niezweryfikowane,
  zapytaj operatora.

## Front: kroki (a) i (b)

```bash
npm i @musikhood-dev/auth-client@^2.3.1 @tanstack/vue-query   # React: @tanstack/react-query
npx @musikhood-dev/auth-client init --dry-run                  # plan — przeczytaj cały raport
npx @musikhood-dev/auth-client init                            # bez --force
```

`latest` w npm to jeszcze 2.1.0 (bez init i 2FA) — zawsze instaluj z wersją. `init` wykrywa: framework, alias,
shadcn/ui albo shadcn-vue, toast faktycznie używany w kodzie, zmienną z adresem API, istniejącą stronę `/login`,
istniejący `lib/auth.ts` i gotowe wpięcie w `main.ts` / `root.tsx`. Wypisuje tylko brakujące kroki. Potem:

- Vue: `app.use(VueQueryPlugin)` **przed** `app.use(createAuth(authClient, { navigate: (p) => router.push(p) }))`,
  `<AuthMfaDialogs />` w `App.vue`. React Router 7: `<AuthProvider client navigate><Outlet /><AuthMfaDialogs /></AuthProvider>`
  w `app/root.tsx`. Dialogi mogą być poza `<AuthBoundary>` (od 2.3.1).
- Trasy chronione w `<AuthBoundary>`, `/login` w `<AuthBoundary mode="guest">`.
- **Gotowe, gdy:** `vue-tsc -b` / `tsc` + build przechodzą, raport `init` nie ma ostrzeżeń, testy ręczne przechodzą.

## Przepisy scalania z istniejącym kodem

- **Istniejący `lib/auth.ts`** (init go pomija): zachowaj `baseUrl` i obecne opcje (`loginPath`, `homePath`,
  `broadcastSession`). Dopisz fragment, który init wypisuje w „Uwaga” (`INLINE_ERRORS`, `reportAuthError`, listener
  `login-error`); istniejący listener `login-error` **zastąp** nim — inaczej błędy pokazywane inline dostaną też
  toast. Zmienną env zostaw obecną (`--env-var` albo wykrycie).
- **Istniejący ekran logowania:** nie podmieniaj go na `LoginForm`. Init wypisuje przepis: w `catch` logowania
  `MfaRequiredError` → return (krok kodu), `MfaEnrollmentRequiredError` → `window.location.assign(enrollmentUrl)`,
  reszta → `loginErrorMessage(e)`; w widoku `stage === 'code'` → `<MfaCodeForm>` zamiast formularza hasła, w tej
  samej karcie (wygląd strony bez zmian). Pełny wzór: `templates/*/LoginForm.vue` / `login-form.tsx` w paczce.
- **Istniejące toasty:** init podpina `reportAuthError` pod toast używany w kodzie (`sonner`, `vue-sonner`, shadcn
  `use-toast`). Paczka toastów tylko w `package.json` (nieużywana) jest pomijana — raport to mówi.
- **Istniejący `security.yaml`** (a): `auth-client:install` nie nadpisze własnych firewalli — wypisze fragment.
  Wklej: provider `auth_client_users: memory: ~`, firewall `login` (wzorzec tras publicznych z
  `Musikhood\AuthClient\Routing\PublicRoutes::pattern()`, `security: false`) **przed** firewallem `api`
  (`custom_authenticators`: `ApiTokenAuthenticator`, `JwtCookieAuthenticator`; `entry_point`:
  `JwtCookieAuthenticator`) i `access_control` (trasy publiczne `PUBLIC_ACCESS`, `^/api` `IS_AUTHENTICATED_FULLY`).
  Sprawdź doctorem: `Trasy publiczne bundla` i `Firewall API` muszą być ✔.
- **Istniejąca encja `User`** (a): tryb bezstanowy nie potrzebuje encji. Jeśli aplikacja ma własną tabelę userów:
  encja implementuje `PanelUserInterface`, repozytorium `PanelUserRepositoryInterface` z `#[AsAlias(id:
  PanelUserRepositoryInterface::class)]` (wzory w `docs/`); migracja tylko za zgodą operatora.

## Pułapki

- **CORS:** `allow_credentials: true`, `X-Device-Fp` w `allow_headers` (auth-client ≥ 2.2 wysyła go zawsze),
  `Retry-After` w `expose_headers` (licznik „spróbuj za N s”). Auth server w wariancie (b) musi to mieć; backend z bundlem —
  `auth-client:install`. Brak `X-Device-Fp` = preflight odrzucony = „logowanie nic nie robi”.
- **Ciasteczka:** HttpOnly, nic w JS. Auth server w wariancie (b) zwykle ustawia `SameSite=None; Secure` i wybiera
  domenę ciasteczka wg nagłówka Origin; localhost = host-only. Bundle: domyślnie `lax` + host-only; front i API na
  subdomenach tej samej domeny → `AUTH_COOKIE_DOMAIN=.example.com` (`lax` wystarcza); różne domeny →
  `same_site: none` + HTTPS. Lokalnie front na `localhost` przeciw zdalnemu API = ciasteczka stron trzecich — przy
  blokadzie 3P logowanie nie przejdzie; wtedy front na domenie, dla której API ustawia ciasteczka, albo lokalne API.
- **Trusted proxies / IP usera:** `SYMFONY_TRUSTED_PROXIES=private_ranges`. Gdy prawdziwe IP klienta ginie przed
  proxy (ingress), auth server traktuje prywatne `X-Client-Ip` jak brak (limit prób zostaje per IP+e-mail).
- **403 panelowe vs `mfa_step_up`:** `panel_access_denied` = brak dostępu (nadaj w panelu administracyjnym,
  propagacja ≤ 30 s); `mfa_step_up` / `mfa_enrollment_required` = polityka 2FA (dialog, sesja żyje). Nie traktuj ich
  jak wylogowania. 403 braku dostępu na zwykłym requeście może nie mieć pola `code` — rozpoznawaj po `/me`.
- **Dialogi 2FA poza `<AuthBoundary>`:** do 2.3.0 `isAuthenticated` poza boundary było zawsze `false`, więc
  `isAuthenticated && stage === 'step-up'` nigdy się nie otwierało (m.in. w panelach z dialogiem w `root.tsx`).
  Naprawione w **2.3.1** — podbij wersję; szablony otwierają dialogi po samym `stage`.
- **Wersje:** `npm i @musikhood-dev/auth-client` bez wersji instaluje `latest` = 2.1.0. Zawsze `@^2.3.1`.
  Bundle ≥ 0.8.1 (`install` / `doctor`, wymagany `AUTH_BASE_URL`).
- **Nie uruchamiaj `init` w panelach, które mają już własne komponenty 2FA** — tylko aktualizacja paczki.
- **Zmienna env:** panele bywają z różnymi nazwami (np. `VITE_BACKEND_URL`, `VITE_API_BASE_URL`, `VITE_API_URL`) — zostaw
  istniejącą, nie wprowadzaj drugiej.
- `VueQueryPlugin` musi być zarejestrowany **przed** `createAuth`.

## Testy ręczne po wdrożeniu

Na dev (konta testowe od operatora; hasła wpisuje człowiek):

1. Konto bez 2FA, polityka `off`/`optional`: logowanie jak dotąd; złe hasło → komunikat pod formularzem, bez toastu.
2. Konto z 2FA: krok kodu; zły kod → „Nieprawidłowy kod”; ponownie użyty kod → komunikat o następnym kodzie.
3. Kod zapasowy: brak checkboxa „Zapamiętaj urządzenie”, logowanie przechodzi, drugi raz ten sam kod nie działa.
4. „Zapamiętaj urządzenie” → wyloguj → zaloguj: bez kodu przez 30 dni.
5. Step-up: zaloguj się w innym panelu bez kodu, wejdź na panel z `required` → dialog „Potwierdź tożsamość”;
   Esc / klik obok nie zamyka; „Wyloguj się” → `/login` bez przeładowania strony.
6. `required` dla konta bez 2FA: przy logowaniu przekierowanie na konfigurację; w trakcie sesji dialog z hasłem.
7. Konto bez dostępu do panelu: 403 → toast z komunikatem API, front na `/login`.
8. Limit prób (429): „Spróbuj ponownie za … s”.
9. Wszystkie dialogi w jasnym i ciemnym motywie; nagłówek `X-Device-Fp` na requestach (DevTools).
10. Backend (a): `auth-client:doctor` zielony na dev i prod.
