<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Security;

use Firebase\JWT\JWT;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use Musikhood\AuthClient\Security\UserTokenVersionStore;
use Musikhood\AuthClient\Tests\Support\JwksTestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class JwtCookieAuthenticatorTest extends TestCase
{
    private const API_TOKEN_HEADER = 'X-Api-Token';
    private const ISSUER = 'https://auth.example';
    private const KID = 'test-kid';

    public function testSupportsReturnsFalseWhenApiTokenHeaderPresent(): void
    {
        $auth = $this->authenticator();

        $request = new Request();
        $request->headers->set(self::API_TOKEN_HEADER, 'mhpat_x');

        // ApiTokenAuthenticator owns this request; stepping aside prevents the
        // cookie flow from overriding its success with a 401.
        self::assertFalse($auth->supports($request));
    }

    public function testSupportsReturnsNullWithoutApiTokenHeader(): void
    {
        $auth = $this->authenticator();

        // Cookie flow untouched: null = always try, so a missing BEARER cookie
        // still yields a 401 on protected routes.
        self::assertNull($auth->supports(new Request()));
    }

    /**
     * KRYTYCZNE dla Fazy 2: ważny master-token usera BEZ lokalnego mirrora i bez
     * dostępu do panelu MUSI przejść authenticate() (bootstrap przez upsert →
     * createFromClaims), żeby flow dotarł do introspekcji (403). Gdyby
     * authenticator robił DB-lookup i rzucał UserNotFoundException (401) PRZED
     * bramką, front zrobiłby refresh → broadcast logout. Tu dowodzimy: brak
     * mirrora → Passport (sukces), NIE wyjątek.
     */
    public function testAuthenticateBootstrapsUserWhenNoLocalMirror(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        self::assertNotFalse($details);

        $userId = Uuid::uuid4();
        $token = JWT::encode([
            'iss' => self::ISSUER,
            'aud' => Uuid::uuid4()->toString(), // OBCY panel — panel-agnostic, przechodzi
            'user_id' => $userId->toString(),
            'email' => 'jan@example.com',
            // brak panel_id — opcjonalny
            'iat' => time(),
            'exp' => time() + 60,
        ], $privateKey, 'RS256', self::KID);

        $jwks = JwksTestFactory::withKey($details['key'], self::KID, self::ISSUER);
        $validator = new JwtValidator($jwks, self::ISSUER);

        // Repo BEZ lokalnego mirrora: findById → null, więc upsert woła createFromClaims.
        $createdUser = $this->createMock(PanelUserInterface::class);
        $createdUser->method('getUserIdentifier')->willReturn('jan@example.com');
        $repo = $this->createMock(PanelUserRepositoryInterface::class);
        $repo->method('findById')->willReturn(null);
        $repo->expects(self::once())->method('createFromClaims')->willReturn($createdUser);
        $repo->expects(self::once())->method('save');
        $repo->expects(self::once())->method('flush');
        $syncer = new UserMirrorSyncer($repo);

        $cookieFactory = new AuthCookieFactory('BEARER', 'refresh_token', '/', null, true, true, 'none');
        $versionStore = new UserTokenVersionStore(new ArrayAdapter()); // brak stored ver → pass

        $authenticator = new JwtCookieAuthenticator(
            $validator,
            $syncer,
            $cookieFactory,
            $versionStore,
            new NullLogger(),
            self::API_TOKEN_HEADER,
        );

        $request = new Request();
        $request->cookies->set('BEARER', $token);

        // BRAK wyjątku (UserNotFoundException ani innego) — authenticate się udaje.
        $passport = $authenticator->authenticate($request);
        self::assertInstanceOf(SelfValidatingPassport::class, $passport);
    }

    public function testDeviceFingerprintEnforceRejectsMismatchWithRecheckCode(): void
    {
        $kit = new \Musikhood\AuthClient\Tests\Support\JwtTestKit();
        $authenticator = $this->deviceAuthenticator($kit, 'enforce');
        $request = new Request();
        $request->cookies->set('BEARER', $kit->token(['fph' => str_repeat('a', 64), 'amr' => ['pwd', 'otp'], 'sid' => 's1']));
        $request->headers->set('X-Device-Fp', str_repeat('b', 64));

        try {
            $authenticator->authenticate($request);
            self::fail('expected exception');
        } catch (\Musikhood\AuthClient\Security\DeviceMismatchAuthenticationException $e) {
            $response = $authenticator->onAuthenticationFailure($request, $e);
            self::assertSame(401, $response->getStatusCode());
            self::assertSame('device_mismatch_recheck', json_decode((string) $response->getContent(), true)['code']);
            self::assertSame([], $response->headers->getCookies());
        }
    }

    public function testDeviceFingerprintObserveMatchOrMissingPasses(): void
    {
        $kit = new \Musikhood\AuthClient\Tests\Support\JwtTestKit();
        $mismatch = new Request();
        $mismatch->cookies->set('BEARER', $kit->token(['fph' => str_repeat('a', 64)]));
        $mismatch->headers->set('X-Device-Fp', str_repeat('b', 64));
        self::assertInstanceOf(SelfValidatingPassport::class, $this->deviceAuthenticator($kit, 'observe')->authenticate($mismatch));

        $match = new Request();
        $match->cookies->set('BEARER', $kit->token(['fph' => str_repeat('a', 64)]));
        $match->headers->set('X-Device-Fp', str_repeat('A', 64));
        self::assertInstanceOf(SelfValidatingPassport::class, $this->deviceAuthenticator($kit, 'enforce')->authenticate($match));

        // Missing header in observe → passes.
        $noHeaderObserve = new Request();
        $noHeaderObserve->cookies->set('BEARER', $kit->token(['fph' => str_repeat('a', 64)]));
        self::assertInstanceOf(SelfValidatingPassport::class, $this->deviceAuthenticator($kit, 'observe')->authenticate($noHeaderObserve));

        // Token without fph (unbound / old) is never checked.
        $unbound = new Request();
        $unbound->cookies->set('BEARER', $kit->token());
        $unbound->headers->set('X-Device-Fp', str_repeat('b', 64));
        self::assertInstanceOf(SelfValidatingPassport::class, $this->deviceAuthenticator($kit, 'enforce')->authenticate($unbound));
    }

    public function testDeviceFingerprintEnforceRejectsMissingHeader(): void
    {
        $kit = new \Musikhood\AuthClient\Tests\Support\JwtTestKit();
        $request = new Request();
        $request->cookies->set('BEARER', $kit->token(['fph' => str_repeat('a', 64)]));

        $this->expectException(\Musikhood\AuthClient\Security\DeviceMismatchAuthenticationException::class);
        $this->deviceAuthenticator($kit, 'enforce')->authenticate($request);
    }

    public function testClaimsExposeAmrSidFph(): void
    {
        $kit = new \Musikhood\AuthClient\Tests\Support\JwtTestKit();
        $claims = $kit->validator->validate($kit->token(['amr' => ['pwd', 'otp'], 'sid' => 'sid-1', 'fph' => str_repeat('c', 64)]));

        self::assertSame(['pwd', 'otp'], $claims->amr);
        self::assertSame('sid-1', $claims->sessionId);
        self::assertSame(str_repeat('c', 64), $claims->deviceFpHash);
    }

    private function deviceAuthenticator(\Musikhood\AuthClient\Tests\Support\JwtTestKit $kit, string $mode): JwtCookieAuthenticator
    {
        return new JwtCookieAuthenticator(
            $kit->validator,
            \Musikhood\AuthClient\Tests\Support\JwtTestKit::syncer($this),
            \Musikhood\AuthClient\Tests\Support\JwtTestKit::cookieFactory(),
            new UserTokenVersionStore(new ArrayAdapter()),
            new NullLogger(),
            self::API_TOKEN_HEADER,
            $mode,
        );
    }

    private function authenticator(): JwtCookieAuthenticator
    {
        // supports() touches none of these collaborators, so we build them
        // without running their (final, dependency-heavy) constructors.
        return new JwtCookieAuthenticator(
            $this->withoutConstructor(JwtValidator::class),
            $this->withoutConstructor(UserMirrorSyncer::class),
            $this->withoutConstructor(AuthCookieFactory::class),
            $this->withoutConstructor(UserTokenVersionStore::class),
            new NullLogger(),
            self::API_TOKEN_HEADER,
        );
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private function withoutConstructor(string $class): object
    {
        return (new \ReflectionClass($class))->newInstanceWithoutConstructor();
    }
}
