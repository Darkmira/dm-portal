<?php

namespace AppBundle\Services;


use Facebook\Exceptions\FacebookResponseException;
use Facebook\Exceptions\FacebookSDKException;
use Facebook\Facebook;
use Facebook\FacebookResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class FacebookFunctions
{
    private $facebook_api_key;
    private $facebook_api_secret;
    private $redirectUrl;
    private $facebook;
    private $session;
    private $helper;
    private $router;

    const DEFAULT_GRAPH_VERSION = 'v2.10';
    const WRITE_PERMISSION = 'publish_actions';

    /**
     * FacebookFunctions constructor.
     * @param $facebook_api_key
     * @param $facebook_api_secret
     * @param $redirectUrl
     * @param $router
     * @param $session
     */
    public function __construct($facebook_api_key, $facebook_api_secret, $redirectUrl, $router, $session)
    {
        $this->facebook_api_key = $facebook_api_key;
        $this->facebook_api_secret = $facebook_api_secret;
        $this->redirectUrl = $redirectUrl;
        $this->router = $router;

        $this->session = new Session();
        $this->facebook = new Facebook([
            'app_id' => $this->facebook_api_key,
            'app_secret' => $this->facebook_api_secret,
            'default_graph_version' => self::DEFAULT_GRAPH_VERSION,
            'fileUpload' => true,
        ]);
        $this->helper = $this->facebook->getRedirectLoginHelper();

    }

    /**
     * @return string
     */
    public function getFacebookLogin(): string
    {
        $permission[] = self::WRITE_PERMISSION;
        $callback = $this->router->generate($this->redirectUrl, array(), UrlGeneratorInterface::ABSOLUTE_URL);

        return $this->helper->getLoginUrl($callback, $permission);
    }

    /**
     * @return mixed
     */
    public function FacebookCallback()
    {
        try {
            $accessToken = $this->helper->getAccessToken();
        } catch (FacebookResponseException $e) {
            echo $e->getMessage();
            exit;
        } catch (FacebookSDKException $e) {
            echo $e->getMessage();
            exit;
        }

        if (!isset($accessToken)) {
            $response = new Response();
            if ($this->helper->getError()) {
                $response->setStatusCode(Response::HTTP_UNAUTHORIZED);
                echo "Error: " . $this->helper->getError() . "\n";
                echo "Error Code: " . $this->helper->getErrorCode() . "\n";
                echo "Error Reason: " . $this->helper->getErrorReason() . "\n";
                echo "Error Description: " . $this->helper->getErrorDescription() . "\n";
            } else {
                $response->setStatusCode(Response::HTTP_BAD_REQUEST);
            }
            $response->send();
            exit;
        }

        $oauth2Client = $this->facebook->getOAuth2Client();
        $tokenMetadata = $oauth2Client->debugToken($accessToken);
        $tokenMetadata->validateAppId($this->facebook_api_key);
        $tokenMetadata->validateExpiration();

        if (!$accessToken->isLongLived()) {
            try {

                $accessToken = $oauth2Client->getLongLivedAccessToken($accessToken);

            } catch (FacebookSDKException $e) {

                return $this->helper->getErrorReason();
            }
        }

        $this->session->set('sessionToken', $accessToken->getValue());

        return $this->session->get('sessionToken');
    }

    /**
     * @param string $message
     * @param string|null $link
     * @param string|null $source
     * @return \Facebook\FacebookResponse|string
     */
    public function postMessageOnFacebookWithLink(string $message, string $link = null, string $source = null)
    {
        $sessionToken = $this->session->get('sessionToken');
        if (!$sessionToken) {
            return $this->getFacebookLogin();
        }

        $linkData = [
            'link' => $link, //The link attached to this post.
            'message' => $message, //The status message in the post.
            'source' => $source //A URL to any Flash movie or video file attached to the post.
        ];

        try {

            return $this->facebook->post('/me/feed', $linkData, $sessionToken);

        } catch (FacebookResponseException $e) {

            return 'Graph returned an error: ' . $e->getMessage();

        } catch (FacebookSDKException $e) {

            return 'Facebook SDK returned an error: ' . $e->getMessage();
        }

    }

    /**
     * @param string $message
     * @param string $image
     * @return \Facebook\FacebookResponse|string
     */
    public function postMessageOnFacebookWithMedia(string $message, string $image)
    {
        $sessionToken = $this->session->get('sessionToken');
        if (!$sessionToken) {
            return $this->getFacebookLogin();
        }

        $data = [
            'message' => $message,
            'source' => $this->facebook->fileToUpload($image),
        ];

        try {

            return $this->facebook->post('/me/photos', $data, $sessionToken);

        } catch (FacebookResponseException $e) {

            return 'Graph returned an error: ' . $e->getMessage();

        } catch (FacebookSDKException $e) {

            return 'Facebook SDK returned an error: ' . $e->getMessage();

        }

    }

}
