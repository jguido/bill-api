<?php
/**
 * Created by PhpStorm.
 * User: dj3
 * Date: 16/05/15
 * Time: 23:30
 */

namespace delt4\RestSecurityBundle\Security\Firewall;


use delt4\RestSecurityBundle\Security\Authentication\ApiUsernamePasswordToken;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class RestSecurityListener implements ListenerInterface
{
    protected $tokenStorage;
    protected $authenticationManager;
    private $trueApikey;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, $trueApikey)
    {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->trueApikey = $trueApikey;

    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        if (!$request->headers->has('Delt4KEY') || '' === $request->headers->get('Delt4KEY'))
        {
            return;
        }
        if ($request->headers->get('Delt4KEY') !== $this->trueApikey)
        {
            return;
        }
        if (!$request->get('_username') || '' === $request->get('_username'))
        {
            return;
        }
        if (!$request->get('_password') || '' === $request->get('_password'))
        {
            return;
        }
        $token = new ApiUsernamePasswordToken(
            $request->get('_username'),
            $request->get('_password'),
            'api',
            [],
            $request->headers->get('Delt4KEY')
        );

        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->tokenStorage->setToken($authToken);

            return;
        } catch (AuthenticationException $failed) {
            //@todo add logger

            // To deny the authentication clear the token. This will redirect to the login page.
            // Make sure to only clear your token, not those of other authentication listeners.
             $token = $this->tokenStorage->getToken();
             if ($token instanceof ApiUsernamePasswordToken && $this->providerKey === $token->getProviderKey()) {
                 $this->tokenStorage->setToken(null);
             }
             return;
        }

        // By default deny authorization
        $response = new Response();
        $response->setStatusCode(Response::HTTP_FORBIDDEN);
        $event->setResponse($response);
    }
}