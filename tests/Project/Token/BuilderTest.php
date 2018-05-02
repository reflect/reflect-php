<?php

declare(strict_types=1);

namespace Reflect\Test\Project\Token;

use Reflect\Project\Token\Builder;
use Reflect\Project\Token\Parameter;
use PHPUnit\Framework\TestCase;

class BuilderTest extends TestCase
{
    /**
     * @var KeyPair
     */
    protected $kp;

    /**
     * @var \Jose\Component\Core\Converter\StandardConverter
     */
    protected $converter;

    /**
     * @var \Jose\Component\Encryption\JWELoader
     */
    protected $loader;

    protected function setUp()
    {
        $keyEncryptionAlgorithmManager = \Jose\Component\Core\AlgorithmManager::create([
            new \Jose\Component\Encryption\Algorithm\KeyEncryption\Dir(),
        ]);

        $contentEncryptionAlgorithmManager = \Jose\Component\Core\AlgorithmManager::create([
            new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM(),
        ]);

        $compressionMethodManager = \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
            new \Jose\Component\Encryption\Compression\Deflate(),
        ]);

        $this->kp = new KeyPair();
        $this->converter = new \Jose\Component\Core\Converter\StandardConverter();

        $serializerManager = \Jose\Component\Encryption\Serializer\JWESerializerManager::create(
            [
                new \Jose\Component\Encryption\Serializer\CompactSerializer($this->converter),
            ]
        );

        $decrypter = new \Jose\Component\Encryption\JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $headerCheckerManager = \Jose\Component\Checker\HeaderCheckerManager::create(
            [
                new \Jose\Component\Checker\AlgorithmChecker(['dir']),
            ],
            [
                new \Jose\Component\Encryption\JWETokenSupport(),
            ]
        );

        $this->loader = new \Jose\Component\Encryption\JWELoader(
            $serializerManager,
            $decrypter,
            $headerCheckerManager
        );
    }

    /**
     * @test
     */
    public function simple()
    {
        $token = (new Builder($this->kp->accessKey->toString()))
            ->build($this->kp->secretKey->toString());

        $jwe = $this->loader->loadAndDecryptWithKey($token, $this->kp->asJWK(), $recipient);
        $this->assertEquals($this->kp->accessKey->toString(), $jwe->getSharedProtectedHeader()['kid']);

        if ($jwe->getPayload() === null) {
            $this->fail('JWT payload is null');
            return;
        }

        $data = $this->converter->decode($jwe->getPayload());
        $this->assertEquals(0, (new \DateTime())->diff((new \DateTime("@${data['iat']}")))->invert);
        $this->assertEquals(0, (new \DateTime())->diff((new \DateTime("@${data['nbf']}")))->invert);
    }

    /**
     * @test
     */
    public function expiration()
    {
        $expiration = new \DateTime();
        $expiration->add(new \DateInterval("PT15M"));

        $token = (new Builder($this->kp->accessKey->toString()))
            ->expiration($expiration)
            ->build($this->kp->secretKey->toString());

        $jwe = $this->loader->loadAndDecryptWithKey($token, $this->kp->asJWK(), $recipient);
        $this->assertEquals($this->kp->accessKey->toString(), $jwe->getSharedProtectedHeader()['kid']);

        if ($jwe->getPayload() === null) {
            $this->fail('JWT payload is null');
            return;
        }

        $data = $this->converter->decode($jwe->getPayload());
        $this->assertEquals($expiration->getTimestamp(), $data['exp']);
    }

    /**
     * @test
     */
    public function claims()
    {
        $parameter = new Parameter(
            'user-id',
            Parameter\Op::EQUALS,
            '1234'
        );

        $token = (new Builder($this->kp->accessKey->toString()))
            ->addViewIdentifier('SecUr3View1D')
            ->setAttribute('user-id', 1234)
            ->setAttribute('user-name', 'Billy Bob')
            ->addParameter($parameter)
            ->build($this->kp->secretKey->toString());

        $jwe = $this->loader->loadAndDecryptWithKey($token, $this->kp->asJWK(), $recipient);
        $this->assertEquals($this->kp->accessKey->toString(), $jwe->getSharedProtectedHeader()['kid']);

        if ($jwe->getPayload() === null) {
            $this->fail('JWT payload is null');
            return;
        }

        $data = $this->converter->decode($jwe->getPayload());
        $this->assertEquals(['SecUr3View1D'], $data[Builder::VIEW_IDENTIFIERS_CLAIM_NAME]);
        $this->assertCount(2, $data[Builder::ATTRIBUTES_CLAIM_NAME]);
        $this->assertEquals(1234, $data[Builder::ATTRIBUTES_CLAIM_NAME]['user-id']);
        $this->assertEquals('Billy Bob', $data[Builder::ATTRIBUTES_CLAIM_NAME]['user-name']);
        $this->assertCount(1, $data[Builder::PARAMETERS_CLAIM_NAME]);
        $this->assertEquals($parameter->jsonSerialize(), $data[Builder::PARAMETERS_CLAIM_NAME][0]);
    }
}
