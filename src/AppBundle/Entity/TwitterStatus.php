<?php

namespace AppBundle\Entity;

use Doctrine\ORM\Id\TableGenerator;
use Doctrine\ORM\Mapping as ORM;

/**
 * TwitterStatus
 *
 * @ORM\Table(name="twitter_status")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\TwitterStatusRepository")
 */
class TwitterStatus
{
    /**
     * @var int
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var string
     *
     * @ORM\Column(name="status", type="string", length=100)
     *
     */
    private $status = 1;


    /**
     * Get id
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param $id
     * @return TableGenerator
     */
    public function setId(int $id): TwitterStatus
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Set status
     *
     * @param string $status
     *
     * @return TwitterStatus
     */
    public function setStatus(string $status): TwitterStatus
    {
        $this->status = $status;

        return $this;
    }

    /**
     * Get status
     *
     * @return string
     */
    public function getStatus()
    {
        return $this->status;
    }
}
