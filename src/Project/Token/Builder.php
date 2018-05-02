<?php

declare(strict_types=1);

namespace Reflect\Project\Token;

class Builder
{
    public const VIEW_IDENTIFIERS_CLAIM_NAME = 'http://reflect.io/s/v3/vid';
    public const PARAMETERS_CLAIM_NAME = 'http://reflect.io/s/v3/p';
    public const ATTRIBUTES_CLAIM_NAME = 'http://reflect.io/s/v3/a';

    /**
     * @var string
     */
    private $accessKey;

    /**
     * @var \DateTime|\DateTimeImmutable|null
     */
    private $expiration = null;

    /**
     * @var string[]
     */
    private $viewIdentifiers = [];

    /**
     * @var Parameter[]
     */
    private $parameters = [];

    /**
     * @var array
     */
    private $attributes = [];

    /**
     * Create a new builder.
     *
     * @param string $accessKey The project access key.
     */
    public function __construct(string $accessKey)
    {
        $this->accessKey = $accessKey;
    }

    /**
     * Sets the expiration time for the token.
     *
     * @param \DateTime|\DateTimeImmutable $when The time for the token to expire.
     * @return Builder This object.
     */
    public function expiration($when): self
    {
        $this->expiration = $when;
        return $this;
    }

    /**
     * Adds a view identifier to the list of view identifiers permitted by
     * this token.
     *
     * If no view identifiers are added to this builder, all views in the given
     * access key's project will be able to be loaded. Otherwise, only those
     * added will be able to be loaded.
     *
     * @param string $id The view identifier to add.
     * @return Builder This object.
     */
    public function addViewIdentifier(string $id): self
    {
        $this->viewIdentifiers[] = $id;
        return $this;
    }

    /**
     * Adds the given parameter to the list of parameters for this token.
     *
     * @param Parameter $parameter The parameter to add.
     * @return Builder This object.
     */
    public function addParameter(Parameter $parameter): self
    {
        $this->parameters[] = $parameter;
        return $this;
    }

    /**
     * Sets a given attribute in this token.
     *
     * @param string $name The attribute name.
     * @param mixed $value The attribute value.
     * @return Builder This object.
     */
    public function setAttribute(string $name, $value): self
    {
        $this->attributes[$name] = $value;
        return $this;
    }

    /**
     * Builds a final copy of the token using the given secret key.
     *
     * @param string $secretKey The secret key that corresponds to this
     *                          builder's access key.
     * @return string The encrypted token.
     */
    public function build(string $secretKey): string
    {
        $converter = new \Jose\Component\Core\Converter\StandardConverter();

        $keyEncryptionAlgorithmManager = \Jose\Component\Core\AlgorithmManager::create([
            new \Jose\Component\Encryption\Algorithm\KeyEncryption\Dir(),
        ]);

        $contentEncryptionAlgorithmManager = \Jose\Component\Core\AlgorithmManager::create([
            new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM(),
        ]);

        $compressionMethodManager = \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
            new \Jose\Component\Encryption\Compression\Deflate(),
        ]);

        $builder = new \Jose\Component\Encryption\JWEBuilder(
            $converter,
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $secretKeyBuffer = \Ramsey\Uuid\Uuid::fromString($secretKey)->getBytes();
        $jwk = \Jose\Component\KeyManagement\JWKFactory::createFromSecret(
            $secretKeyBuffer,
            [
                'use' => 'enc',
            ]
        );

        $now = (new \DateTime())->getTimestamp();
        $data = [
            'iat' => $now,
            'nbf' => $now,
        ];

        if ($this->expiration !== null) {
            $data['exp'] = $this->expiration->getTimestamp();
        }

        if (!empty($this->viewIdentifiers)) {
            $data[self::VIEW_IDENTIFIERS_CLAIM_NAME] = $this->viewIdentifiers;
        }

        if (!empty($this->parameters)) {
            $data[self::PARAMETERS_CLAIM_NAME] = $this->parameters;
        }

        if (!empty($this->attributes)) {
            $data[self::ATTRIBUTES_CLAIM_NAME] = $this->attributes;
        }

        $jwe = $builder
            ->create()
            ->withPayload($converter->encode($data))
            ->withSharedProtectedHeader([
                'alg' => 'dir',
                'enc' => 'A128GCM',
                'zip' => 'DEF',
                'cty' => 'JWT',
                'kid' => $this->accessKey,
            ])
            ->addRecipient($jwk)
            ->build();

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer($converter);
        return $serializer->serialize($jwe, 0);
    }
}
