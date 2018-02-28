<?php

namespace AppBundle\Services;

use \Abraham\TwitterOAuth\TwitterOAuth;
use AppBundle\Entity\Suggestion;
use AppBundle\Entity\TwitterStatus;
use Doctrine\ORM\EntityManager;

class TwitterFunctions
{
    private $consumer_secret;
    private $consumer_key;
    private $access_token;
    private $token_secret;
    private $oauth;
    private $manager;
    private $query;
    private $suggestionDirectory;

    const PUBLISHED_STATUS = 2;


    /**
     * TwitterFunctions constructor.
     * @param $consumer_key
     * @param $consumer_secret
     * @param $access_token
     * @param $token_secret
     */
    public function __construct($consumer_key, $consumer_secret, $access_token, $token_secret, EntityManager $manager, $suggestionDirectory, QueryService $query)
    {
        $this->consumer_key = $consumer_key;
        $this->consumer_secret = $consumer_secret;
        $this->access_token = $access_token;
        $this->token_secret = $token_secret;
        $this->manager = $manager;
        $this->query = $query;
        $this->suggestionDirectory = $suggestionDirectory;

        $this->oauth = new TwitterOAuth($this->consumer_key, $this->consumer_secret, $this->access_token, $this->token_secret);
    }

    /**
     * @param $tweet
     * @return array|object
     */
    public function postTweetWithoutMedia($tweet)
    {
        return $this->oauth->post('statuses/update', ['status' => $tweet]);
    }

    /**
     * @param $tweet
     * @param $media
     * @return array|object
     */
    public function postTweetWithMedia($tweet, $media)
    {
        $file = $this->oauth->upload('media/upload', ['media' => $media]);

        return $this->oauth->post('statuses/update', ['status' => $tweet, 'media_ids' => $file->media_id]);
    }

    /**
     * @return array|object
     */
    public function autoPostOnTwitter()
    {
        /** @var Suggestion $pendingTopics */
        $pendingTopics = $this->manager->getRepository('AppBundle:Suggestion')->findTwitterPending();

        foreach ($pendingTopics as $topic) {
            $file = $topic->getFile() . '.' . $topic->getFileExtension();

            //to make sure that the additional description exists
            if ($topic->getAdditionalDescription() != null) {

                $tweet = $topic->getAdditionalDescription();

            } else {

                $tweet = $topic->getDescription();
            }

            if ($topic->getFile() != null) {

                $media = $this->suggestionDirectory . '/' . $file;

                /** @var TwitterStatus $twitterStatus */
                $twitterStatus = $this->query->findOneOrException(TwitterStatus::class, ['id' => self::PUBLISHED_STATUS]);

                $topic->setTwitterStatus($twitterStatus);
                $this->query->save($topic);

                return $this->postTweetWithMedia($tweet, $media);

            } else {

                /** @var TwitterStatus $twitterStatus */
                $twitterStatus = $this->query->findOneOrException(TwitterStatus::class, ['id' => self::PUBLISHED_STATUS]);

                $topic->setTwitterStatus($twitterStatus);
                $this->query->save($topic);

                return $this->postTweetWithoutMedia($tweet);
            }

        }

    }
}
