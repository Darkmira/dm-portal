<?php

namespace tests\AppBundle\Controller;

use AppBundle\Entity\Article;
use AppBundle\Entity\ArticleVote;
use AppBundle\Repository\ArticleVoteRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ArticleControllerTest extends WebTestCase
{
    private $client;

    protected function setUp()
    {
        $this->client = static::createClient();
        $this->client->followRedirects(true);
        \Tests\AppBundle\Utils\Database::prepareDb($this->client);
    }

    /*
     * URL : GET /articles
     * Test to display all articles
     */
    public function testShowArticles()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $crawler = $this->client->request('GET', '/articles');
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertContains('Articles', $crawler->filter('h2')->text());
    }

    /*
     * URL : GET /article/{id}
     * Test to display an article
     */
    public function testShowArticle()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $crawler = $this->client->request('GET', '/articles/6');
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertContains('Le super article de Xu', $crawler->filter('h1')->text());
    }

    /*
     * URL : POST /articles/add
     * Test the creation of an article
     */
    public function testCreateArticle()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $crawler = $this->client->request('GET', '/articles/add');
        $form = $crawler->filter('form')->form();
        $form->setValues([
            'app_article' => [
                'title' => 'Article1',
                'category' => 1,
                'description' => 'description'
            ]
        ]);
        $this->client->submit($form);

        $article = \Tests\AppBundle\Utils\Database::getLast($this->client, Article::class);
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertEquals('Article1', $article->getTitle());
        $this->assertEquals(1, $article->getCategory()->getId());
        $this->assertEquals('description', $article->getDescription());
    }

    /*
     * URL : POST /articles/add
     * Test the creation of an article with the field 'title' leave blank
     */
    public function testCreateArticleWithoutTitle()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $crawler = $this->client->request('GET', '/articles/add');
        $form = $crawler->filter('form')->form();
        $form->setValues([
            'app_article' => [
                'category' => 1,
                'description' => 'description'
            ]
        ]);
        $crawler = $this->client->submit($form);

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertEquals('/articles/add', $this->client->getRequest()->getRequestUri());
        $this->assertContains('Cette valeur ne doit pas être vide.', $crawler->filter('html')->text());
    }

    /*
     * URL : POST /articles/add
     * Test the creation of an article with the field 'description' leave blank
     */
    public function testCreateArticleWithoutDescription()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $crawler = $this->client->request('GET', '/articles/add');
        $form = $crawler->filter('form')->form();
        $form->setValues([
            'app_article' => [
                'title' => 'Article1',
                'category' => 1
            ]
        ]);
        $crawler = $this->client->submit($form);

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertEquals('/articles/add', $this->client->getRequest()->getRequestUri());
        $this->assertContains('Cette valeur ne doit pas être vide.', $crawler->filter('html')->text());
    }

    /**
     * URL : POST /articles/{id}/votes/add
     * test the vote with different values ​​for the parameter "isAccepted"
     *
     * @dataProvider addVoteProvider
     */
    public function testAddVote($vote, $expected)
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);
        $crawler = $this->client->request('POST', '/articles/3/votes/add');

        $form = $crawler->filter('form[name="app_article_vote"]')->form();
        $form->setValues([
            'app_article_vote' => [
                'isAccepted' => $vote
            ]
        ]);
        $crawler = $this->client->submit($form);
        $currentUser = \Tests\AppBundle\Utils\Auth::getUser($this->client);
        $em = $this->client->getContainer()->get('doctrine.orm.entity_manager');
        $vote = $em->getRepository(ArticleVote::class)
            ->findOneBy(['user' => $currentUser, 'article' => 3]);

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertEquals(count($vote), 1);
        $this->assertEquals($vote->isAccepted(), $expected);
    }

    /**
     * Data provider
     */
    public function addVoteProvider()
    {
        return [
            [1, true],
            [0, false],
            [3, true],
            ['a', true]
        ];
    }

    /**
     * URL : POST /articles/{id}/votes/add
     * test the vote without the parameter "isAccepted"
     *
     * @dataProvider addVoteProvider
     */
    public function testAddVoteWithoutIsAccepted($vote, $expected)
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);
        $nb1 = \Tests\AppBundle\Utils\Database::count($this->client, ArticleVote::class);

        $crawler = $this->client->request('POST', '/articles/3/votes/add');
        $form = $crawler->filter('form[name="app_article_vote"]')->form();
        $crawler = $this->client->submit($form);

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $nb2 = \Tests\AppBundle\Utils\Database::count($this->client, ArticleVote::class);
        $this->assertEquals($nb1, $nb2);
    }

    /**
     * URL : POST /articles/{id}/votes/add
     * submit 2 form and only one vote should be in database
     *
     */
    public function testNoInsertManyVotes()
    {
        \Tests\AppBundle\Utils\Auth::logIn($this->client);

        $nb1 = \Tests\AppBundle\Utils\Database::count($this->client, ArticleVote::class);

        for ($iteration = 0; $iteration < 2; $iteration++) {
            $crawler = $this->client->request('POST', '/articles/3/votes/add');

            $form = $crawler->filter('form[name="app_article_vote"]')->form();
            $form->setValues([
                'app_article_vote' => [
                    'isAccepted' => 1
                ]
            ]);
            $crawler = $this->client->submit($form);
        }

        $nb2 = \Tests\AppBundle\Utils\Database::count($this->client, ArticleVote::class);

        $this->assertEquals($nb1 + 1, $nb2);
    }
}
