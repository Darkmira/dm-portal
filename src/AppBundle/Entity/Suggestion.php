<?php
namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Suggestion
 *
 * @ORM\Table(name="suggestion")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\SuggestionRepository")
 */
class Suggestion
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->insertedAt = new \Datetime;
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
     * @ORM\Column(name="description", type="text", nullable=true)
     * @Assert\Expression(
     *     expression="this.getDescription() != null || this.getFile() != null",
     *     message="suggestions.form.not.blank.description.and.file"
     * )
     */
    private $description;

    /**
     * @ORM\Column(type="string")
     *
     * @ORM\Column(name="description", type="text", nullable=true)
     * @Assert\Expression(
     *     expression="this.getDescription() != null || this.getFile() != null",
     *     message="suggestions.form.not.blank.description.and.file"
     * )
     */
    private $file;

    /**
     * @ORM\Column(type="string", name="file_extension", type="string", nullable=true)
     */
    private $fileExtension;

    /**
     * @ORM\Column(type="string", name="file_mime_type", type="string", nullable=true)
     */
    private $fileMimeType;


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
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\SuggestionStatus")
     * @ORM\JoinColumn(nullable=false)
     */
    private $status;

    /**
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\SuggestionCategory", inversedBy="suggestions")
     * @ORM\JoinColumn(nullable=false)
     * @Assert\NotNull()
     */
    private $category;
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
     * Set description
     *
     * @param string $description
     *
     * @return Suggestion
     */
    public function setDescription($description): Suggestion
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
     * Get file
     *
     * @return string
     */
    public function getFile()
    {
        return $this->file;
    }

    /**
     * Set file
     *
     * @param string $file
     *
     * @return Suggestion
     */
    public function setFile($file): Suggestion
    {
        $this->file = $file;

        return $this;
    }

    /**
     * Get file extension
     *
     * @return string
     */
    public function getFileExtension()
    {
        return $this->fileExtension;
    }

    /**
     * Set file mime type
     *
     * @param string $mimeType
     *
     * @return Suggestion
     */
    public function setFileMimeType($mimeType): Suggestion
    {
        $this->mimeType = $mimeType;

        return $this;
    }

    /**
     * Get file mime type
     *
     * @return string
     */
    public function getFileMimeType()
    {
        return $this->fileMimeType;
    }

    /**
     * Set file extension
     *
     * @param string $fileExtension
     *
     * @return Suggestion
     */
    public function setFileExtension($fileExtension): Suggestion
    {
        $this->fileExtension = $fileExtension;

        return $this;
    }

    /**
     * Set insertedAt
     *
     * @param \DateTime $insertedAt
     *
     * @return Suggestion
     */
    public function setInsertedAt(\DateTime $insertedAt): Suggestion
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
     * @return Suggestion
     */
    public function setUser(User $user): Suggestion
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
     * Set status
     *
     * @param \AppBundle\Entity\SuggestionStatus $status
     *
     * @return Suggestion
     */
    public function setStatus(SuggestionStatus $status): Suggestion
    {
        $this->status = $status;

        return $this;
    }

    /**
     * Get status
     *
     * @return \AppBundle\Entity\SuggestionStatus
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * Set category
     *
     * @param \AppBundle\Entity\SuggestionCategory $category
     *
     * @return Suggestion
     */
    public function setCategory(SuggestionCategory $category): Suggestion
    {
        $this->category = $category;

        return $this;
    }

    /**
     * Get category
     *
     * @return \AppBundle\Entity\SuggestionCategory
     */
    public function getCategory()
    {
        return $this->category;
    }
}

