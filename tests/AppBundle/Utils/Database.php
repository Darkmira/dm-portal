<?php
namespace Tests\AppBundle\Utils;

use \Symfony\Bundle\FrameworkBundle\Client;

class Database
{
    public static function prepareDb(Client $client)
    {
        $client->getContainer()->get('khepin.yaml_loader')->purgeDatabase('orm');
        $client->getContainer()->get('khepin.yaml_loader')->loadFixtures('test');
    }

    public static function getLast(Client $client, $repository)
    {
        $em = $client->getContainer()->get('doctrine.orm.entity_manager');

        return $em->getRepository($repository)->findOneBy(
            [],
            ['id' => 'DESC']
        );
    }

    public static function count(Client $client, $repository)
    {
        $em = $client->getContainer()->get('doctrine.orm.entity_manager')
            ->getRepository($repository);

        return $query = $em->createQueryBuilder('t')
            ->select('COUNT(t)')
            ->getQuery()
            ->getSingleScalarResult();
    }
}
