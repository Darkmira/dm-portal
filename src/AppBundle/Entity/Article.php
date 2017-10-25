<?php

namespace AppBundle\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Article
 *
 * @ORM\Table(name="article")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\ArticleRepository")
 */
class Article
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->insertedAt = new \Datetime;
        $this->votes = new ArrayCollection();
    }

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
     * @ORM\Column(name="title", type="string", length=255)
     * @Assert\NotBlank()
     */
    private $title;

    /**
     * @var string
     *
     * @ORM\Column(name="description", type="text")
     * @Assert\NotBlank()
     */
    private $description;

    /**
     * @var string
     *
     * @ORM\Column(name="link", type="string", length=255, nullable=true)
     */
    private $link;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="inserted_at", type="datetime")
     */
    private $insertedAt;

    /**
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\User")
     * @ORM\JoinColumn(nullable=false)
     */
    private $user;

    /**
     * @ORM\OneToMany(targetEntity="AppBundle\Entity\ArticleVote", mappedBy="article")
     */
    private $votes;

    /**
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\ArticleCategory", inversedBy="articles")
     * @ORM\JoinColumn(nullable=false)
     * @Assert\NotNull()
     */
    private $category;

    /**
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\ArticleStatus")
     * @ORM\JoinColumn(nullable=false)
     */
    private $status;


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
     * Set title
     *
     * @param string $title
     *
     * @return Article
     */
    public function setTitle(string $title): Article
    {
        $this->title = $title;

        return $this;
    }

    /**
     * Get title
     *
     * @return string
     */
    public function getTitle()
    {
        return $this->title;
    }

    /**
     * Set description
     *
     * @param string $description
     *
     * @return Article
     */
    public function setDescription(string $description): Article
    {
        $this->description = $description;

        return $this;
    }

    /**
     * Get description
     *
     * @return string
     */
    public function getDescription()
    {
        return $this->description;
    }

    /**
     * Set link
     *
     * @param string $link
     *
     * @return Article
     */
    public function setLink(string $link): Article
    {
        $this->link = $link;

        return $this;
    }

    /**
     * Get link
     *
     * @return string
     */
    public function getLink()
    {
        return $this->link;
    }

    /**
     * Set insertedAt
     *
     * @param \DateTime $insertedAt
     *
     * @return Article
     */
    public function setInsertedAt(\DateTime $insertedAt): Article
    {
        $this->insertedAt = $insertedAt;

        return $this;
    }

    /**
     * Get insertedAt
     *
     * @return \DateTime
     */
    public function getInsertedAt(): \DateTime
    {
        return $this->insertedAt;
    }

    /**
     * Set User
     *
     * @param \AppBundle\Entity\User $user
     *
     * @return Article
     */
    public function setUser(User $user): Article
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Get User
     *
     * @return \AppBundle\Entity\User
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get votes
     *
     * @return \Doctrine\Common\Collections\Collection
     */
    public function getVotes()
    {
        return $this->votes;
    }

    /**
     * Get accepted votes
     *
     * @return \Doctrine\Common\Collections\Collection
     */
    public function getAcceptedVotes()
    {
        $votes = new ArrayCollection();
        foreach ($this->votes as $vote) {
            if ($vote->isAccepted()) {
                $votes[] = $vote;
            }
        }

        return $votes;
    }

    /**
     * Get refused votes
     *
     * @return \Doctrine\Common\Collections\Collection
     */
    public function getRefusedVotes()
    {
        $votes = new ArrayCollection();
        foreach ($this->votes as $vote) {
            if (!$vote->isAccepted()) {
                $votes[] = $vote;
            }
        }

        return $votes;
    }

    /**
     * Set category
     *
     * @param \AppBundle\Entity\ArticleCategory $category
     *
     * @return Article
     */
    public function setCategory(ArticleCategory $category): Article
    {
        $this->category = $category;

        return $this;
    }

    /**
     * Get category
     *
     * @return \AppBundle\Entity\ArticleCategory
     */
    public function getCategory()
    {
        return $this->category;
    }

    /**
     * Set status
     *
     * @param \AppBundle\Entity\ArticleStatus $status
     *
     * @return Article
     */
    public function setStatus(ArticleStatus $status): Article
    {
        $this->status = $status;

        return $this;
    }

    /**
     * Get status
     *
     * @return \AppBundle\Entity\ArticleStatus
     */
    public function getStatus()
    {
        return $this->status;
    }
}
