<?php
namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * SuggestionStatus
 *
 * @ORM\Table(name="suggestion_status")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\SuggestionStatusRepository")
 */
class SuggestionStatus
{
    /**
     * @var int
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     */
    private $id;

    /**
     * @var string
     *
     * @ORM\Column(name="label", type="string", length=255, unique=true)
     */
    private $label;


    /**
     * Set id
     *
     * @param int $id
     * @return SuggestionStatus
     */
    public function setId(int $id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Get id
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Set label
     *
     * @param string $label
     *
     * @return SuggestionStatus
     */
    public function setLabel(string $label): SuggestionStatus
    {
        $this->label = $label;

        return $this;
    }

    /**
     * Get label
     *
     * @return string
     */
    public function getLabel()
    {
        return $this->label;
    }
}
