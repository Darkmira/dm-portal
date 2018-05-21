<?php

namespace AppBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;

class GoogleController extends Controller
{
    /**
     * Link to this controller to start the "connect" process
     *
     * @Route("/sign-in/google", name="sign_in_google")
     */
    public function connectAction()
    {
        // will redirect to Google
        return $this->get('oauth2.registry')
            ->getClient('google') // key used in config.yml
            ->redirect();
    }

    /**
     * After going to Google, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config.yml
     *
     * @Route("/sign-in-check/google", name="sign_in_check_google")
     */
    public function connectCheckAction(Request $request)
    {

    }
}