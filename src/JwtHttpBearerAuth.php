<?php

namespace yzh52521\jwt;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation;
use Throwable;
use Yii;
use yii\base\InvalidConfigException;
use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;
use yii\web\IdentityInterface;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
use yii\web\User;

use function call_user_func;
use function get_class;

/**
 * JwtHttpBearerAuth is an action filter that supports the authentication method based on HTTP Bearer JSON Web Token.
 *
 * You may use JwtHttpBearerAuth by attaching it as a behavior to a controller or module, like the following:
 *
 * ```php
 * public function behaviors()
 * {
 *     return [
 *         'JWTBearerAuth' => [
 *             'class' => \yzh52521\jwt\JwtHttpBearerAuth::class,
 *         ],
 *     ];
 * }
 * ```
 *
 * @author Paweł Bizley Brzozowski <pawel@positive.codes> since 2.0 (fork)
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 */
class JwtHttpBearerAuth extends HttpBearerAuth
{
    /**
     * @var string|array<string, mixed>|Jwt application component ID of the JWT handler, configuration array, or
     * JWT handler object itself. By default, it's assumes that component of ID "jwt" has been configured.
     */
    public $jwt = 'jwt';

    /**
     * @var (callable(): mixed)|null anonymous function that should return identity of user authenticated with the JWT
     * payload information. It should have the following signature:
     *
     * ```php
     * function (Token $token)
     * ```
     *
     * where $token is JSON Web Token provided in the HTTP header.
     * If $auth is not provided method User::loginByAccessToken() will be called instead.
     */
    public $auth;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        if (empty($this->pattern)) {
            throw new InvalidConfigException('You must provide pattern to use to extract the HTTP authentication value!');
        }
    }

    private ?Jwt $JWTComponent = null;

    public function getJwtComponent(): Jwt
    {
        if ($this->JWTComponent === null) {
            /** @var Jwt $jwt */
            $jwt = Instance::ensure($this->jwt, Jwt::class);
            $this->JWTComponent = $jwt;
        }

        return $this->JWTComponent;
    }

    /**
     * Authenticates the current user.
     * @param User $user
     * @param Request $request
     * @param Response $response
     * @return IdentityInterface|null the authenticated user identity. If authentication information is not provided, null will be returned.
     * @throws InvalidConfigException When JWT configuration has not been properly initialized.
     * @throws CannotDecodeContent When something goes wrong while decoding token.
     * @throws Token\InvalidTokenStructure When token string structure is invalid.
     * @throws Token\UnsupportedHeaderFound When parsed token has an unsupported header.
     * @throws Validation\RequiredConstraintsViolated When constraint is not present in token.
     * @throws Validation\NoConstraintsGiven When no constraints are provided.
     * @throws Validation\ConstraintViolation When constraint is violated.
     * @throws UnauthorizedHttpException if authentication information is provided but is invalid.
     */
    public function authenticate($user, $request, $response): ?IdentityInterface // BC signature
    {
        /** @var string|null $authHeader */
        $authHeader = $request->getHeaders()->get($this->header);

        if ($authHeader === null || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        $identity = null;
        $token = null;

        try {
            $token = $this->processToken($matches[1]);
        } catch (Throwable $exception) {
            Yii::warning($exception->getMessage(), 'JwtHttpBearerAuth');
            throw $exception;
        }

        if ($token !== null) {
            if (is_callable($this->auth, true)) {
                $identity = call_user_func($this->auth, $token);
            } else {
                $identity = $user->loginByAccessToken($token->toString(), get_class($this));
            }
        }

        if (!$identity instanceof IdentityInterface) {
            return null;
        }

        return $identity;
    }

    /**
     * Parses and validates the JWT token.
     * @param string $data data provided in HTTP header, presumably JWT
     * @throws InvalidConfigException
     */
    public function processToken(string $data): ?Token
    {
        $token = $this->getJwtComponent()->parse($data);

        return $this->getJwtComponent()->validate($token) ? $token : null;
    }

    /**
     * @throws UnauthorizedHttpException
     */
    public function fail(Response $response): void
    {
        $this->challenge($response);
        $this->handleFailure($response);
    }

    /**
     * Handles authentication failure.
     * @param Response $response
     * @throws UnauthorizedHttpException
     */
    public function handleFailure($response): void // BC signature
    {
        throw new UnauthorizedHttpException('Your request was made with invalid or expired JSON Web Token.');
    }
}