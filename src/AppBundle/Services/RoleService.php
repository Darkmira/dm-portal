<?php
namespace AppBundle\Services;

use AppBundle\AppBundle;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class RoleService
{
    private $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * return an exception if user is not admin
     * @throws NotFoundHttpException
     */
    public function adminOrException()
    {
        /** @var \AppBundle\Entity\User $user */
        $user = $this->container->get('security.token_storage')->getToken()->getUser();

        if (!$user->isAdmin()) {
            throw new NotFoundHttpException("Permission denied");
        }
    }

}
