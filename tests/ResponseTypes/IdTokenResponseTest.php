<?php

namespace OpenIDConnectServer\Test\ResponseTypes;

use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\Test\Stubs\IdentityProvider;
use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\CryptKey;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use Psr\Http\Message\ResponseInterface;
use Laminas\Diactoros\Response;

class IdTokenResponseTest extends TestCase
{
    /**
     * @dataProvider provideCryptKeys
     */
    public function testGeneratesDefaultHttpResponse($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
    }

    /**
     * @dataProvider provideCryptKeys
     */
    public function testOpenIDConnectHttpResponse($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey, ['openid']);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
        self::assertObjectHasAttribute('id_token', $json);
    }

    // test additional claims
    // test fails without claimsetinterface
    /**
     * @dataProvider provideCryptKeys
     */
    public function testThrowsRuntimeExceptionWhenMissingClaimSetInterface($privateKey)
    {
        $this->expectException(\RuntimeException::class);

        $_SERVER['HTTP_HOST'] = 'https://localhost';
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_CLAIMSET),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, $privateKey, ['openid']);
        self::fail('Exception should have been thrown');
    }

    // test fails without identityinterface
    /**
     * @dataProvider provideCryptKeys
     */
    public function testThrowsRuntimeExceptionWhenMissingIdentifierSetInterface($privateKey)
    {
        $this->expectException(\RuntimeException::class);
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_IDENTIFIER),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, $privateKey, ['openid']);
        self::fail('Exception should have been thrown');
    }

    /**
     * @dataProvider provideCryptKeys
     */
    public function testClaimsGetExtractedFromUserEntity($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey, ['openid', 'email']);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(),false);

        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
        self::assertObjectHasAttribute('id_token', $json);

        if (class_exists("\Lcobucci\JWT\Token\Parser")) {
            $parser = new \Lcobucci\JWT\Token\Parser(new \Lcobucci\JWT\Encoding\JoseEncoder, \Lcobucci\JWT\Encoding\ChainedFormatter::withUnixTimestampDates());
        } else {
            $parser = new \Lcobucci\JWT\Parser();
        }

        $token = $parser->parse($json->id_token);
        self::assertTrue($token->claims()->has("email"));
    }

    public static function provideCryptKeys()
    {
        return array(
            array(new CryptKey('file://'.__DIR__.'/../Stubs/private.key')),
            array(new CryptKey(
                <<<KEY
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkJwkYf/HF2lYi
/W9MCe7ok9v67++RgDdriz/IhIbcWI4e/jlZ1S3w9Lauc2i42bOZwvJ7SFVY5TSk
RfGxBsLE4gcslEQqGRMyswra+BlCxCUNTpwHEdWOpSJVKH5Txa+uSf5XDVuh0UeI
U57zp+XsDwmRPvxTFpxGtrqGv7pzyJ7rG+zv9u/CgWn9OOqE3xZfYadRaBuTfkPi
vGwXjJJ6UCcaXDLea87uU1s9ebDvVD72C8mvmki9m33giZNNjWEXMvpGKqzPXx6m
64PJqmuZGZyQsTiaeanADpFwDZJtWLBxIry5UAGx18MreguXIFlNTE80tTNir2FV
rS26l6RjAgMBAAECggEALVjc4/O6OFsXN8krr+9hfvS0ioHaGg9j9Iou2UoODAnF
5b8d4w8OHJBnJvFlZShQHEW1MG/GFu8nsWb9jPQNDljmmCO4EK3/NNqFU9RwIOcf
fi+br4QJ8Fo+IrLzuO7X5kpqtR7Akb8o+p20QDWk63BptGbSfClIUn3LQTEmfBCJ
7IhevCoLbw14vxZc7VcRvrfU63BdV2UdL5CjyraI0mTa6RUq4Ufo4a90G8RjePAp
d8Nv1tO6nn0RARbUlqSTGRdBm/gprj/J1ZtLWtOw3hgikcTzBPtx7LAgvjTRiEZA
/XaFn/v+FUJB0AqUZFpbrI4DXgDxvhUNkc4VPiStIQKBgQD8VEFUMApUW43dsaJl
d4xWXrkweeolj0tLUcG2HACaha+RYOROzsLm7suYZNAwDJX4LI+TKmnUhtEpwJob
sB6qEzoZ1qLn0qZNNAE0Ghzrf/iJRHgKcsUR//eJvZjUyVjlX2wb9EyLdTAqE23w
aJ7OpeFe6uyKA54SNCnnv7++qQKBgQDneL1eDirMCpqQLPJgqRfPGao9eCZVJEOL
81OOGYfj0AosqSeg9P6rMyHsXmkimpWqWcJ/+l5z70J1LZPuDedFgaBil9LPv7q+
FToVZH89Ac0QvqcQevxZA+5cCoyk2zpzxrAU8rviYej7boNGAcLUD0U01moiumYt
d9XpzYZuKwKBgAZLh9G03R0bp59nRhjn8Z1aAZ6+++Nx/rvjT0Tez/kK6sViuG9q
4xvlyziDE1qPhdJKMk7GmRtPPbqf7nhQXYN6tVFdtHS6IaH9cSY+nIgXijjKd4Az
Os1nKGLMUxrD5y7ZwZW084/rHYd/Mpfz1DptkwDONZZ/3pqvqHf6par5AoGBAN1A
EKn9mrTMEe9rtwXjuwlPO+VjmihZ8GKuZBh4mOaNrZwA2AtHAsI7rtpTZ+UWo6Zg
A8T2WSAx+3Er7rFmAsDyZY64Fl5TorkcaxeVpvV2aj/uLJxZIion0seRodvWXSnb
KeXsGuEJu3vRp5LcDhFKw1j89hhZ2V7uo77GoA9fAoGAfGEHM7gG5J/zpJ8kYOsO
d10UVlvQ6SLCf3HPjq6sH0zbeRjux2NUQ14SoHjgkKuKjvpMzYGi96Ak1xkxRhg2
iokTNwAtNXm4Ac+7oL62aMfKhPgX/KCJ08lDqG/los98tFuVnlxTSIj3GwfDSCrp
mDyeJtWjCy3ECKZujHs2zw0=
-----END RSA PRIVATE KEY-----
KEY
            ),
        ));
    }

    private function processResponseType($responseType, $privateKey,  array $scopeNames = ['basic'])
    {
        $_SERVER['HTTP_HOST'] = 'https://localhost';

        $responseType->setPrivateKey($privateKey);

        // league/oauth2-server 5.1.0 does not support this interface
        if (method_exists($responseType, 'setEncryptionKey')) {
            $responseType->setEncryptionKey(base64_encode(random_bytes(36)));
        }

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $scopes = [];
        foreach ($scopeNames as $scopeName) {
            $scope = new ScopeEntity();
            $scope->setIdentifier($scopeName);
            $scopes[] = $scope;
        }

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');

        if (method_exists($accessToken, 'setPrivateKey')) {
            $accessToken->setPrivateKey($privateKey);
        }

        // Use DateTime for older libraries, DateTimeImmutable for new ones.
        try {
            $accessToken->setExpiryDateTime(
                (new \DateTime())->add(new \DateInterval('PT1H'))
            );
        } catch(\TypeError $e) {
            $accessToken->setExpiryDateTime(
                (new \DateTimeImmutable())->add(new \DateInterval('PT1H'))
            );
        }
        $accessToken->setClient($client);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);

        // Use DateTime for older libraries, DateTimeImmutable for new ones.
        try {
            $refreshToken->setExpiryDateTime(
                (new \DateTime())->add(new \DateInterval('PT1H'))
            );
        } catch(\TypeError $e) {
            $refreshToken->setExpiryDateTime(
                (new \DateTimeImmutable())->add(new \DateInterval('PT1H'))
            );
        }

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType->generateHttpResponse(new Response());
    }
}
