<?php

namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * FacebookStatus
 *
 * @ORM\Table(name="facebook_status")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\FacebookStatusRepository")
 */
class FacebookStatus
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
     */
    private $status = self::DEFAULT_STATUS;


    const DEFAULT_STATUS = 1;


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
     * @param int $id
     * @return FacebookStatus
     */
    public function setId(int $id): FacebookStatus
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Set status
     *
     * @param string $status
     *
     * @return FacebookStatus
     */
    public function setStatus($status): FacebookStatus
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
