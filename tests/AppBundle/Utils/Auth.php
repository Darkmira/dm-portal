<?php

namespace Tests\AppBundle\Utils;

use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use \Symfony\Bundle\FrameworkBundle\Client;

class Auth
{
    CONST EMAIL = 'fdanguiral@darkmira.com';
    CONST FIREWALL_CONTEXT = 'main';

    public static function getUser(Client $client)
    {
        $user = $client->getContainer()
            ->get('doctrine.orm.entity_manager')
            ->getRepository('AppBundle:User')
            ->findOneBy(['email' => Auth::EMAIL]);

        if (!$user) {
            throw new \Exception('User not found');
        }
        return $user;
    }

    public static function logIn(Client $client)
    {
        $session = $client->getContainer()->get('session');
        $user = self::getUser($client);

        $token = new UsernamePasswordToken($user, null, self::FIREWALL_CONTEXT);
        $session->set('_security_' . self::FIREWALL_CONTEXT, serialize($token));
        $session->save();

        $cookie = new Cookie($session->getName(), $session->getId());
        $client->getCookieJar()->set($cookie);
    }
}
