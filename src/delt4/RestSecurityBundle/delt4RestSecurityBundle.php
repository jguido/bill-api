<?php

namespace delt4\RestSecurityBundle;

use delt4\RestSecurityBundle\DependencyInjection\Factory\RestSecurityFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class delt4RestSecurityBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new RestSecurityFactory());
    }
}
