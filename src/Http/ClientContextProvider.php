<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Http;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dane przeglądarki end-usera, które bundle przekazuje do auth servera przy
 * wywołaniach `/api/auth/backend/*` (auth server ufa im wyłącznie po poprawnym
 * HTTP Basic panelu):
 *   - `X-Client-Ip`          — Request::getClientIp() konsumenta (honoruje jego trusted_proxies),
 *   - `X-Client-User-Agent`  — User-Agent przeglądarki,
 *   - `X-Device-Fp`          — hash fingerprintu z nagłówka przeglądarki (auth-client >= 2.2),
 * oraz `device` (komponenty fingerprintu) z body żądania przeglądarki.
 * Brak bieżącego requestu (CLI) → brak nagłówków (zachowanie jak w 0.6).
 */
final readonly class ClientContextProvider
{
    public const HEADER_DEVICE_FP = 'X-Device-Fp';

    public function __construct(
        private RequestStack $requestStack,
    ) {}

    /**
     * @return array<string, string>
     */
    public function forwardedHeaders(): array
    {
        $request = $this->requestStack->getMainRequest();
        if (!$request instanceof Request) {
            return [];
        }

        $headers = [];
        $ip = $request->getClientIp();
        if (null !== $ip && '' !== $ip) {
            $headers['X-Client-Ip'] = $ip;
        }
        $ua = $request->headers->get('User-Agent');
        if (null !== $ua && '' !== $ua) {
            $headers['X-Client-User-Agent'] = mb_substr($ua, 0, 512);
        }
        $fp = $this->deviceFpHeader();
        if (null !== $fp) {
            $headers[self::HEADER_DEVICE_FP] = $fp;
        }

        return $headers;
    }

    public function deviceFpHeader(): ?string
    {
        $value = $this->requestStack->getMainRequest()?->headers->get(self::HEADER_DEVICE_FP);
        if (null === $value) {
            return null;
        }
        $value = strtolower(trim($value));

        return 1 === preg_match('/^[a-f0-9]{64}$/', $value) ? $value : null;
    }

    /**
     * `device` z JSON body przeglądarki (login / refresh / 2FA) albo null.
     *
     * @return array<string, mixed>|null
     */
    public function deviceFromBody(): ?array
    {
        $request = $this->requestStack->getMainRequest();
        if (!$request instanceof Request) {
            return null;
        }

        $content = $request->getContent();
        if ('' === $content) {
            return null;
        }

        try {
            $decoded = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        $device = is_array($decoded) ? ($decoded['device'] ?? null) : null;
        if (!is_array($device) || [] === $device) {
            return null;
        }

        /** @var array<string, mixed> $device */
        return $device;
    }
}
