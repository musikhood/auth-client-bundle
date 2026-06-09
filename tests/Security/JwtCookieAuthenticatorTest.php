<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Security;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use Musikhood\AuthClient\Security\UserTokenVersionStore;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;

final class JwtCookieAuthenticatorTest extends TestCase
{
    private const API_TOKEN_HEADER = 'X-Api-Token';

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
