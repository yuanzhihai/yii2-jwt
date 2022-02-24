<?php

namespace yzh52521\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

use function array_keys;
use function count;
use function in_array;
use function is_array;
use function is_callable;
use function is_string;
use function reset;
use function strpos;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v4.
 * @see https://github.com/lcobucci/jwt
 *
 */
class Jwt extends Component
{
    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';
    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';
    public const EDDSA = 'EdDSA';

    public const STORE_IN_MEMORY = 'in_memory';
    public const STORE_LOCAL_FILE_REFERENCE = 'local_file_reference'; // deprecated since 3.2.0, will be removed in 4.0.0

    public const METHOD_PLAIN = 'plain';
    public const METHOD_BASE64 = 'base64';
    public const METHOD_FILE = 'file';

    public const SYMMETRIC = 'symmetric';
    public const ASYMMETRIC = 'asymmetric';

    public const KEY = 'key';
    public const STORE = 'store';
    public const METHOD = 'method';
    public const PASSPHRASE = 'passphrase';

    /**
     * @var string|array<string, string>|Signer\Key Signing key definition.
     * This can be a simple string, an instance of Key, or a configuration array.
     * The configuration takes the following array keys:
     * - 'key'        => Key's value or path to the key file.
     * - 'store'      => Either `Jwt::STORE_IN_MEMORY` or `Jwt::STORE_LOCAL_FILE_REFERENCE` (deprecated) -
     *                   whether to keep the key in the memory or as a reference to a local file.
     * - 'method'     => `Jwt::METHOD_PLAIN`, `Jwt::METHOD_BASE64`, or `Jwt::METHOD_FILE` - whether the key is a plain
     *                   text, base64 encoded text, or a file.
     *                   In case the 'store' is set to `Jwt::STORE_LOCAL_FILE_REFERENCE` (deprecated), only
     *                   `Jwt::METHOD_FILE` method is available.
     * - 'passphrase' => Key's passphrase.
     * In case a simple string is provided (and it does not start with 'file://' or '@') the following configuration
     * is assumed:
     * [
     *      'key' => // the original given value,
     *      'store' => Jwt::STORE_IN_MEMORY,
     *      'method' => Jwt::METHOD_PLAIN,
     *      'passphrase' => '',
     * ]
     * In case a simple string is provided and it does start with 'file://' (direct file path) or '@' (Yii alias)
     * the following configuration is assumed:
     * [
     *      'key' => // the original given value,
     *      'store' => Jwt::STORE_IN_MEMORY,
     *      'method' => Jwt::METHOD_FILE,
     *      'passphrase' => '',
     * ]
     * If you want to override the assumed configuration, you must provide it directly.
     * @since 3.0.0
     */
    public $signingKey = '';

    /**
     * @var string|array<string, string>|Signer\Key Verifying key definition.
     * $signingKey documentation you can find above applies here as well.
     * Symmetric algorithms (like HMAC) use a single key to sign and verify tokens so this property is ignored in that
     * case. Asymmetric algorithms (like RSA and ECDSA) use a private key to sign and a public key to verify.
     * @since 3.0.0
     */
    public $verifyingKey = '';

    /**
     * @var string|Signer|null Signer ID or Signer instance to be used for signing/verifying.
     * See $signers for available values. In case it's not set, no algorithm will be used, which may be handy if you
     * want to do some testing, but it's NOT recommended for production environments.
     * @since 3.0.0
     */
    public $signer;

    /**
     * @var array<string, string[]> Default signers configuration. When instantiated it will use selected array to
     * spread into `Yii::createObject($type, array $params = [])` method so the first array element is $type, and
     * the second is $params.
     * Since 3.0.0 configuration is done using arrays.
     * @since 2.0.0
     */
    public array $signers = [
        self::HS256 => [Signer\Hmac\Sha256::class],
        self::HS384 => [Signer\Hmac\Sha384::class],
        self::HS512 => [Signer\Hmac\Sha512::class],
        self::RS256 => [Signer\Rsa\Sha256::class],
        self::RS384 => [Signer\Rsa\Sha384::class],
        self::RS512 => [Signer\Rsa\Sha512::class],
        self::ES256 => [Signer\Ecdsa\Sha256::class],
        self::ES384 => [Signer\Ecdsa\Sha384::class],
        self::ES512 => [Signer\Ecdsa\Sha512::class],
        self::EDDSA => [Signer\Eddsa::class],
    ];

    /**
     * @var array<string, array<int, string>> Algorithm types.
     * @since 3.0.0
     */
    public array $algorithmTypes = [
        self::SYMMETRIC  => [
            self::HS256,
            self::HS384,
            self::HS512,
        ],
        self::ASYMMETRIC => [
            self::RS256,
            self::RS384,
            self::RS512,
            self::ES256,
            self::ES384,
            self::ES512,
            self::EDDSA,
        ],
    ];

    /**
     * @var string|array<string, mixed>|Encoder|null Custom encoder.
     * It can be component's ID, configuration array, or instance of Encoder.
     * In case it's not an instance, it must be resolvable to an Encoder's instance.
     * @since 3.0.0
     */
    public $encoder;

    /**
     * @var string|array<string, mixed>|Decoder|null Custom decoder.
     * It can be component's ID, configuration array, or instance of Decoder.
     * In case it's not an instance, it must be resolvable to a Decoder's instance.
     * @since 3.0.0
     */
    public $decoder;

    /**
     * @var array<array<mixed>|(callable(): mixed)|string>|(callable(): mixed)|null List of constraints that
     * will be used to validate against or an anonymous function that can be resolved as such list. The signature of
     * the function should be `function(\bizley\jwt\Jwt $jwt)` where $jwt will be an instance of this component.
     * For the constraints you can use instances of Lcobucci\JWT\Validation\Constraint or configuration arrays to be
     * resolved as such.
     * @since 3.0.0
     */
    public $validationConstraints;

    private ?Configuration $configuration = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        if ($this->signer === null) {
            $this->configuration = Configuration::forUnsecuredSigner($this->prepareEncoder(), $this->prepareDecoder());
        } else {
            $signerId = $this->signer;
            if ($this->signer instanceof Signer) {
                $signerId = $this->signer->algorithmId();
            }
            if (in_array($signerId, $this->algorithmTypes[self::SYMMETRIC], true)) {
                $this->configuration = Configuration::forSymmetricSigner(
                    $this->prepareSigner($this->signer),
                    $this->prepareKey($this->signingKey),
                    $this->prepareEncoder(),
                    $this->prepareDecoder()
                );
            } elseif (in_array($signerId, $this->algorithmTypes[self::ASYMMETRIC], true)) {
                $this->configuration = Configuration::forAsymmetricSigner(
                    $this->prepareSigner($this->signer),
                    $this->prepareKey($this->signingKey),
                    $this->prepareKey($this->verifyingKey),
                    $this->prepareEncoder(),
                    $this->prepareDecoder()
                );
            } else {
                throw new InvalidConfigException('Invalid signer ID!');
            }
        }
    }

    /**
     * @param array<array<mixed>|(callable(): mixed)|string> $config
     * @return object
     * @throws InvalidConfigException
     */
    private function buildObjectFromArray(array $config): object
    {
        $keys = array_keys($config);
        if (is_string(reset($keys))) {
            // most probably Yii-style config
            return Yii::createObject($config);
        }

        return Yii::createObject(...$config);
    }

    /**
     * @throws InvalidConfigException
     * @since 3.0.0
     */
    public function getConfiguration(): Configuration
    {
        if ($this->configuration === null) {
            throw new InvalidConfigException('Configuration has not been set up. Did you call init()?');
        }

        return $this->configuration;
    }

    /**
     * Since 3.0.0 this method is using different signature.
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for details of using the builder.
     * @throws InvalidConfigException
     */
    public function getBuilder(?ClaimsFormatter $claimFormatter = null): Builder
    {
        return $this->getConfiguration()->builder($claimFormatter);
    }

    /**
     * Since 3.0.0 this method is using different signature.
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for details of using the parser.
     * @throws InvalidConfigException
     */
    public function getParser(): Parser
    {
        return $this->getConfiguration()->parser();
    }

    /**
     * @throws CannotDecodeContent When something goes wrong while decoding.
     * @throws Token\InvalidTokenStructure When token string structure is invalid.
     * @throws Token\UnsupportedHeaderFound When parsed token has an unsupported header.
     * @throws InvalidConfigException
     * @since 3.0.0
     */
    public function parse(string $jwt): Token
    {
        return $this->getParser()->parse($jwt);
    }

    /**
     * This method goes through every single constraint in the set, groups all the violations, and throws an exception
     * with the grouped violations.
     * @param string|Token $jwt JWT string or instance of Token
     * @throws Validation\RequiredConstraintsViolated When constraint is violated
     * @throws Validation\NoConstraintsGiven When no constraints are provided
     * @throws InvalidConfigException
     * @since 3.0.0
     */
    public function assert($jwt): void
    {
        $configuration = $this->getConfiguration();
        $token         = $jwt instanceof Token ? $jwt : $this->parse($jwt);
        $constraints   = $this->prepareValidationConstraints();
        $configuration->validator()->assert($token, ...$constraints);
    }

    /**
     * This method return false on first constraint violation
     * @param string|Token $jwt JWT string or instance of Token
     * @throws InvalidConfigException
     * @since 3.0.0
     */
    public function validate($jwt): bool
    {
        $configuration = $this->getConfiguration();
        $token         = $jwt instanceof Token ? $jwt : $this->parse($jwt);
        $constraints   = $this->prepareValidationConstraints();

        return $configuration->validator()->validate($token, ...$constraints);
    }

    /**
     * Prepares key based on the definition.
     * @param string|array<string, string>|Signer\Key $key
     * @return Signer\Key
     * @throws InvalidConfigException
     * @since 2.0.0
     * Since 3.0.0 this method is private and using different signature.
     */
    private function prepareKey($key): Signer\Key
    {
        if ($key instanceof Signer\Key) {
            return $key;
        }

        if (is_string($key)) {
            if ($key === '') {
                throw new InvalidConfigException('Empty string used as a key configuration!');
            }
            if (strpos($key, '@') === 0) {
                $keyConfig = [
                    self::KEY    => Yii::getAlias($key),
                    self::STORE  => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_FILE,
                ];
            } elseif (strpos($key, 'file://') === 0) {
                $keyConfig = [
                    self::KEY    => $key,
                    self::STORE  => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_FILE,
                ];
            } else {
                $keyConfig = [
                    self::KEY    => $key,
                    self::STORE  => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_PLAIN,
                ];
            }
        } elseif (is_array($key)) {
            $keyConfig = $key;
        } else {
            throw new InvalidConfigException('Invalid key configuration!');
        }

        $value      = $keyConfig[self::KEY] ?? '';
        $store      = $keyConfig[self::STORE] ?? self::STORE_IN_MEMORY;
        $method     = $keyConfig[self::METHOD] ?? self::METHOD_PLAIN;
        $passphrase = $keyConfig[self::PASSPHRASE] ?? '';

        if (!is_string($value)) {
            throw new InvalidConfigException('Invalid key value!');
        }
        if (!in_array($store, [self::STORE_IN_MEMORY, self::STORE_LOCAL_FILE_REFERENCE], true)) {
            throw new InvalidConfigException('Invalid key store!');
        }
        if (!in_array($method, [self::METHOD_PLAIN, self::METHOD_BASE64, self::METHOD_FILE], true)) {
            throw new InvalidConfigException('Invalid key method!');
        }
        if (!is_string($passphrase)) {
            throw new InvalidConfigException('Invalid key passphrase!');
        }

        if ($store === self::STORE_IN_MEMORY) {
            if ($method === self::METHOD_BASE64) {
                return Signer\Key\InMemory::base64Encoded($value, $passphrase);
            }
            if ($method === self::METHOD_FILE) {
                return Signer\Key\InMemory::file($value, $passphrase);
            }

            return Signer\Key\InMemory::plainText($value, $passphrase);
        }

        if ($method !== self::METHOD_FILE) {
            throw new InvalidConfigException('Invalid key store and method combination!');
        }

        return Signer\Key\LocalFileReference::file($value, $passphrase);
    }

    /**
     * @param string|Signer $signer
     * @return Signer
     * @throws InvalidConfigException
     */
    private function prepareSigner($signer): Signer
    {
        if ($signer instanceof Signer) {
            return $signer;
        }

        if (in_array($signer, [self::ES256, self::ES384, self::ES512], true)) {
            Yii::$container->set(Signer\Ecdsa\SignatureConverter::class, Signer\Ecdsa\MultibyteStringConverter::class);
        }

        /** @var Signer $signerInstance */
        $signerInstance = $this->buildObjectFromArray($this->signers[$signer]);

        return $signerInstance;
    }

    /**
     * Use RSA encryption
     * @return bool
     * @throws InvalidConfigException
     */
    private function RSASigner()
    {
        return $this->getConfiguration()->signer() instanceof Rsa;
    }


    /**
     * Default check constaints
     * @throws InvalidConfigException
     */
    private function defaultValidationConstraints()
    {
        $this->getConfiguration()->setValidationConstraints(
            new SignedWith($this->getConfiguration()->signer(),$this->RSASigner() ? $this->getConfiguration()->verificationKey() :$this->getConfiguration()->signingKey()),
        );
    }

    /**
     * @return Validation\Constraint[]
     * @throws InvalidConfigException
     */
    private function prepareValidationConstraints(): array
    {
        $this->defaultValidationConstraints();
        $configuredConstraints = $this->getConfiguration()->validationConstraints();
        if (count($configuredConstraints)) {
            return $configuredConstraints;
        }

        if (is_array($this->validationConstraints)) {
            $constraints = [];

            foreach ($this->validationConstraints as $constraint) {
                if ($constraint instanceof Validation\Constraint) {
                    $constraints[] = $constraint;
                } else {
                    /** @var Validation\Constraint $constraintInstance */
                    $constraintInstance = $this->buildObjectFromArray($constraint);
                    $constraints[]      = $constraintInstance;
                }
            }

            return $constraints;
        }

        if (is_callable($this->validationConstraints)) {
            /** @phpstan-ignore-next-line */
            return call_user_func($this->validationConstraints, $this);
        }
        return [];
    }

    /**
     * @throws InvalidConfigException
     */
    private function prepareEncoder(): ?Encoder
    {
        if ($this->encoder === null) {
            return null;
        }

        /** @var Encoder $encoder */
        $encoder = Instance::ensure($this->encoder, Encoder::class);

        return $encoder;
    }

    /**
     * @throws InvalidConfigException
     */
    private function prepareDecoder(): ?Decoder
    {
        if ($this->decoder === null) {
            return null;
        }

        /** @var Decoder $decoder */
        $decoder = Instance::ensure($this->decoder, Decoder::class);

        return $decoder;
    }
}