<?php
namespace AppBundle\Services;

use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class QueryService
{
    private $container;
    private $em;

    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->em = $this->container->get('doctrine')->getManager();
    }

    /**
     * return object or exception
     * @param String $class
     * @param array $params
     * @return $class
     * @throws NotFoundHttpException
     */
    public function findOneOrException(String $class, Array $params)
    {
        $classRepository = $this->em->getRepository($class);
        $object = $classRepository->findOneBy($params);

        if (!$object) {
            throw new NotFoundHttpException("Object($class) not found");
        }

        return $object;
    }

    /**
     * return object or create one
     * @param $class
     * @param array $params
     * @return $class
     * @throws \Exception
     */
    public function findOneOrCreate($class, Array $params) {
        if(!class_exists($class)) {
            throw new \Exception("class($class) don't exist");
        }

        $classRepository = $this->em->getRepository($class);
        $object = $classRepository->findOneBy($params);
        if(!$object) {
            $object = new $class();
        }

        return $object;
    }

    /**
     * check if exist in databse
     * @param $class
     * @param array $params
     * @return boolean
     * @throws \Exception
     */
    public function checkIfExist($class, Array $params) {
        if(!class_exists($class)) {
            throw new \Exception("class($class) don't exist");
        }

        $classRepository = $this->em->getRepository($class);
        $object = $classRepository->findOneBy($params);
        if(!$object) {
            return false;
        }

        return true;
    }

    /**
     * Save object
     * @param $object
     */
    public function save($object) {
        $this->em->persist($object);
        $this->em->flush();
    }
}
