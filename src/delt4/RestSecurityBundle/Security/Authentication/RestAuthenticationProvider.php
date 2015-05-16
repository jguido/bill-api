<?php
/**
 * Created by PhpStorm.
 * User: dj3
 * Date: 16/05/15
 * Time: 23:43
 */

namespace delt4\RestSecurityBundle\Security\Authentication;


use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class RestAuthenticationProvider implements AuthenticationProviderInterface {

    protected $userProvider;
    private $trueApikey;

    public function __construct(UserProviderInterface $userProvider, $trueApikey)
    {
        $this->userProvider = $userProvider;
        $this->trueApikey = $trueApikey;
    }


    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     *
     * @return TokenInterface An authenticated TokenInterface instance, never null
     *
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        if ($user && $this->validateUser($user, $token))
        {
            $authenticatedToken = new ApiUsernamePasswordToken(
                $user->getUsername(),
                $token->getCredentials(),
                'api',
                $user->getRoles(),
                $this->trueApikey
            );
            $token->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('bad_api_key.');
    }

    /**
     * @param UserInterface $user
     * @param TokenInterface $token
     * @return bool
     */
    private final function validateUser(UserInterface $user, TokenInterface $token)
    {
        return $user->getPassword() === $token->getCredentials();
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return bool true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof ApiUsernamePasswordToken;
    }
}