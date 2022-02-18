# yii2-jwt
JWT Integration for Yii 2
![Latest Stable Version](https://img.shields.io/packagist/v/yzh52521/jwt.svg)
[![Total Downloads](https://img.shields.io/packagist/dt/yzh52521/jwt.svg)](https://packagist.org/packages/yzh52521/jwt)
![License](https://img.shields.io/packagist/l/yzh52521/jwt.svg)
[![Infection MSI](https://badge.stryker-mutator.io/github.com/yzh52521/yii2-jwt/master)](https://infection.github.io)

# JWT Integration For Yii 2

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for
[Yii 2 framework](https://www.yiiframework.com).

> This is a fork of [yzh52521/yii2-jwt](https://github.com/yzh52521/yii2-jwt) package

## Installation

Add the package to your `composer.json`:

    {
        "require": {
            "yzh52521/jwt": "^1.0"
        }
    }

and run `composer update` or alternatively run `composer require yzh52521/jwt:^1.0`

## Basic usage

Add `jwt` component to your configuration file:

    [
        'components' => [
            'jwt' => [
                'class' => \yzh52521\jwt\Jwt::class,
                'signer' => ... // Signer ID
                'signingKey' => ... // Secret key string or path to the signing key file
            ],
        ],
    ],


### Available signers

Symmetric:
- HMAC (HS256, HS384, HS512)

Asymmetric:
- RSA (RS256, RS384, RS512)
- ECDSA (ES256, ES384, ES512)
- EdDSA (since 3.1.0)

Signer IDs are available as constants (like Jwt::HS256).

You can also provide your own signer, either as an instance of Lcobucci\JWT\Signer or by adding its config to `signers`
and `algorithmTypes` and using its ID for `signer`.

### Keys

For symmetric signers `signingKey` is required. For asymmetric ones you also need to set `verifyingKey`. Keys can be
provided as simple strings, configuration arrays, or instances of Lcobucci\JWT\Signer\Key.

Configuration array can be as the following:

```php
[
    'key' => /* key content */,
    'passphrase' => /* key passphrase */,
    'store' => /* storage type */,
    'method' => /* method type */,
]
```

- key (Jwt::KEY) - _string_, default `''`,
- passphrase (Jwt::PASSPHRASE) - _string_, default `''`,
- store (Jwt::STORE) - _string_, default `Jwt::STORE_IN_MEMORY`,
  available: `Jwt::STORE_IN_MEMORY`, `Jwt::STORE_LOCAL_FILE_REFERENCE` (deprecated since 3.2.0, will be removed in 4.0.0)
  (see https://lcobucci-jwt.readthedocs.io/en/latest/configuration/)
- method (Jwt::METHOD) - _string_, default `Jwt::METHOD_PLAIN`,
  available: `Jwt::METHOD_PLAIN`, `Jwt::METHOD_BASE64`, `Jwt::METHOD_FILE`
  (see https://lcobucci-jwt.readthedocs.io/en/latest/configuration/)

Simple string keys are shortcuts to the following array configs:
- key starts with `@` or `file://`:
  ```php
  [
      'key' => /* given key itself */,
      'passphrase' => '',
      'store' => Jwt::STORE_IN_MEMORY,
      'method' => Jwt::METHOD_FILE,
  ]
  ```
  Detecting `@` at the beginning assumes Yii alias has been provided so it will be resolved with `Yii::getAlias()`.

- key doesn't start with `@` nor `file://`:
  ```php
  [
      'key' => /* given key itself */,
      'passphrase' => '',
      'store' => Jwt::STORE_IN_MEMORY,
      'method' => Jwt::METHOD_PLAIN,
  ]
  ```

### Issuing a token example:

```php
$now = new \DateTimeImmutable();
/** @var \Lcobucci\JWT\Token\Plain $token */
$token = Yii::$app->jwt->getBuilder()
    // Configures the issuer (iss claim)
    ->issuedBy('http://example.com')
    // Configures the audience (aud claim)
    ->permittedFor('http://example.org')
    // Configures the id (jti claim)
    ->identifiedBy('4f1g23a12aa')
    // Configures the time that the token was issue (iat claim)
    ->issuedAt($now)
    // Configures the time that the token can be used (nbf claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute'))
    // Configures the expiration time of the token (exp claim)
    ->expiresAt($now->modify('+1 hour'))
    // Configures a new claim, called "uid"
    ->withClaim('uid', 1)
    // Configures a new header, called "foo"
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken(
        Yii::$app->jwt->getConfiguration()->signer(),
        Yii::$app->jwt->getConfiguration()->signingKey()
    );
$tokenString = $token->toString();
```

See https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for more info.

### Parsing a token

```php
/** @var string $jwt */
/** @var \Lcobucci\JWT\Token $token */
$token = Yii::$app->jwt->parse($jwt);
```

See https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for more info.

### Validating a token

You can validate a token or perform an assertion on it (see https://lcobucci-jwt.readthedocs.io/en/latest/validating-tokens/).

For validation use:
```php
/** @var \Lcobucci\JWT\Token | string $token */                                      
/** @var bool $result */
$result = Yii::$app->jwt->validate($token);
```

For assertion use:
```php
/** @var \Lcobucci\JWT\Token | string $token */                                      
Yii::$app->jwt->assert($token);
```

## Using component for REST authentication

Configure the `authenticator` behavior in the controller.

```php
class ExampleController extends Controller
{
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        
        $behaviors['authenticator'] = [
            'class' => \yzh52521\jwt\JwtHttpBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

There are special options available:
- jwt - _string_ ID of component (default with `'jwt'`), component configuration _array_, or an instance of `yzh52521\jwt\Jwt`,
- auth - callable or `null` (default) - anonymous function with signature `function (\Lcobucci\JWT\Token $token)` that
  should return identity of user authenticated with the JWT payload information. If $auth is not provided method
  `yii\web\User::loginByAccessToken()` will be called instead.

For other configuration options refer to the [Yii 2 Guide](https://www.yiiframework.com/doc/guide/2.0/en/rest-authentication).

## JWT Usage

Please refer to the [lcobucci/jwt Documentation](https://lcobucci-jwt.readthedocs.io/en/latest/).

## JSON Web Tokens

- https://jwt.io
