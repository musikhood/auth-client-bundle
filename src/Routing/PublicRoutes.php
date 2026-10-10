<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Routing;

/**
 * Single source of truth for the bundle routes that must be reachable WITHOUT
 * a valid access token. Used by `auth-client:install` (security.yaml),
 * `auth-client:doctor` (coverage check), AuthValidationListener (introspection
 * gate exclusions) and the tests.
 *
 * Why public:
 *   - login / login/mfa: no session yet (mfa_token authorizes the second step);
 *   - logout, token/refresh, token/invalidate: run while the access token may
 *     already be expired;
 *   - session/mfa, mfa/enrollment/request: authorize with the refresh_token
 *     cookie verified by the auth server — behind the JWT gate the 2FA policy
 *     would answer 403 mfa_step_up on the step-up itself;
 *   - auth-client/webhook/user-invalidated: authorized by the auth server's
 *     signed JWT, not by a user session.
 */
final class PublicRoutes
{
    /** @var list<string> */
    public const PATHS = [
        '/api/login',
        '/api/login/mfa',
        '/api/logout',
        '/api/token/refresh',
        '/api/token/invalidate',
        '/api/session/mfa',
        '/api/mfa/enrollment/request',
        '/api/auth-client/webhook/user-invalidated',
    ];

    /** A bundle-protected route used to verify the authenticated part of the firewall. */
    public const PROTECTED_PROBE_PATH = '/api/v1/user/me';

    /**
     * Anchored regex matching exactly {@see PATHS} — for a security firewall
     * `pattern` and an `access_control` `path`.
     */
    public static function pattern(): string
    {
        // The paths contain no regex metacharacters (only letters, '/', '-'),
        // so they are used verbatim — the pattern stays readable in security.yaml.
        $alternatives = array_map(
            static fn (string $path): string => substr($path, \strlen('/api/')),
            self::PATHS,
        );

        return '^/api/(' . implode('|', $alternatives) . ')$';
    }

    public static function isPublic(string $path): bool
    {
        return \in_array($path, self::PATHS, true);
    }
}
