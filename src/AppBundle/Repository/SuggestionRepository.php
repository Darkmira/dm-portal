<?php

namespace AppBundle\Repository;


use AppBundle\Entity\Suggestion;
use Doctrine\ORM\EntityRepository;
use Doctrine\DBAL\Types\DateTimeType;

class SuggestionRepository extends EntityRepository
{
    /**
     * @return Suggestion[]
     */
    public function findFacebookPending()
    {
        return  $this->createQueryBuilder('s')
            ->where('s.startTime <= :now')
            ->andWhere('s.facebookStatus = 1')
            ->setParameter('now', new \DateTime('now'), DateTimeType::DATETIME)
            ->orderBy('s.insertedAt')
            ->getQuery()
            ->getResult();
    }

    /**
     * @return Suggestion[]
     */
    public function findTwitterPending()
    {
        return  $this->createQueryBuilder('s')
            ->where('s.startTime <= :now')
            ->andWhere('s.twitterStatus = 1')
            ->setParameter('now', new \DateTime('now'), DateTimeType::DATETIME)
            ->orderBy('s.insertedAt')
            ->getQuery()
            ->getResult();
    }
}
