<?php
/**
 * Created by PhpStorm.
 * User: dj3
 * Date: 16/05/15
 * Time: 23:57
 */

namespace delt4\RestSecurityBundle\DependencyInjection\Factory;


use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class RestSecurityFactory implements SecurityFactoryInterface {

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.rest.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('rest.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProvider))
        ;

        $listenerId = 'security.authentication.listener.rest.'.$id;
        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('rest.security.authentication.listener'));

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    /**
     * Defines the position at which the provider is called.
     * Possible values: pre_auth, form, http, and remember_me.
     *
     * @return string
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'api';
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        // TODO: Implement addConfiguration() method.
    }
}