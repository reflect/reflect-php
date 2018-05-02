<?php

declare(strict_types=1);

namespace Reflect\Test\Project\Token;

class KeyPair
{
    /**
     * @var \Ramsey\Uuid\UuidInterface
     */
    public $accessKey;

    /**
     * @var \Ramsey\Uuid\UuidInterface
     */
    public $secretKey;

    public function __construct()
    {
        $this->accessKey = \Ramsey\Uuid\Uuid::uuid4();
        $this->secretKey = \Ramsey\Uuid\Uuid::uuid4();
    }

    public function asJWK(): \Jose\Component\Core\JWK
    {
        return \Jose\Component\KeyManagement\JWKFactory::createFromSecret(
            $this->secretKey->getBytes(),
            [
                'use' => 'enc',
            ]
        );
    }
}
