<?php

namespace AppBundle\Controller;

use AppBundle\Entity\ArticleVote;
use AppBundle\Form\Type\ArticleType;
use AppBundle\Entity\Article;
use AppBundle\Form\Type\ArticleVoteType;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;


class ArticleController extends Controller
{
    /**
     * @Route("/articles", name="get_articles")
     * @Method({"GET"})
     * @return Response
     */
    public function getArticlesAction(): Response
    {
        $articles = $this->getDoctrine()->getRepository('AppBundle:Article')
            ->findAll();

        return $this->render('AppBundle:Article:get_articles.html.twig', [
            'articles' => $articles
        ]);
    }

    /**
     * @Route("/articles/add", name="post_articles")
     * @Method({"GET", "POST"})
     * @param Request $request
     * @return Response
     */
    public function postArticlesAction(Request $request): Response
    {
        $article = new Article();
        $form = $this->createForm(ArticleType::class, $article);

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $em = $this->getDoctrine()->getManager();
            $status = $em->getRepository('AppBundle:ArticleStatus')
                ->find(1);
            $article->setUser($this->getUser());
            $article->setStatus($status);
            $em->persist($article);
            $em->flush();

            $this->sendMailNewArticle($article);

            return $this->redirectToRoute('get_articles');
        }

        return $this->render('AppBundle:Article:post_articles.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route("/articles/{id}", name="get_article")
     * @Method({"GET", "POST"})
     * @param int $id
     * @return Response
     */
    public function getArticleAction(int $id): Response
    {
        $article = $this->getDoctrine()->getRepository('AppBundle:Article')
            ->find($id);

        if (!$article) {
            $this->articleNotFound();
        }

        $myVote = $this->getDoctrine()->getRepository('AppBundle:ArticleVote')
            ->findOneBy([
                'article' => $article,
                'user' => $this->getUser()
            ]);

        return $this->render('AppBundle:Article:get_article.html.twig', [
            'article' => $article,
            'myVote' => $myVote
        ]);
    }

    /**
     * @Route("/articles/{id}/votes/add", name="post_article_votes")
     * @Method({"GET", "POST"})
     * @param Int $id
     * @param Request $request
     * @return Response
     */
    public function postArticleVotesAction(int $id, Request $request): Response
    {
        $article = $this->getDoctrine()->getRepository('AppBundle:Article')
            ->find($id);

        if (!$article) {
            $this->articleNotFound();
        }

        $myVote = $this->getDoctrine()->getRepository('AppBundle:ArticleVote')
            ->findOneBy([
                'article' => $article,
                'user' => $this->getUser()
            ]);

        if ($article->getStatus()->getId() == 1) {
            $articleVote = new ArticleVote();
            $articleVote->setArticle($article);
            $articleVote->setUser($this->getUser());
            $form = $this->createForm(ArticleVoteType::class, $articleVote, [
                'action' => $this->generateUrl('post_article_votes', [
                    'id' => $article->getId()
                ])
            ]);

            $form->handleRequest($request);
            if ($form->isSubmitted() && $form->isValid()) {
                $this->get('role_service')->adminOrException();
                $em = $this->getDoctrine()->getManager();
                $em->persist($articleVote);
                $em->flush();

                $this->sendMailVoteArticle($articleVote);

                return $this->redirectToRoute('get_article', [
                    'id' => $article->getId()
                ]);
            }
        }

        $params = [
            'article' => $article,
            'myVote' => $myVote
        ];
        if (isset($form)) {
            $params['form'] = $form->createView();
        }

        return $this->render('AppBundle:Article/Partial:post_article_votes.html.twig', $params);
    }

    /**
     * @Route("/articles/{id}/status", name="patch_article_status")
     * @Method({"GET", "POST"})
     * @param Int $id
     * @param Request $request
     * @return Response
     */
    public function patchArticleStatusAction(int $id, Request $request): Response
    {
        $article = $this->getDoctrine()->getRepository('AppBundle:Article')
            ->find($id);

        if (!$article) {
            $this->articleNotFound();
        }

        $myVote = $this->getDoctrine()->getRepository('AppBundle:ArticleVote')
            ->findOneBy([
                'article' => $article,
                'user' => $this->getUser()
            ]);

        if ($article->getStatus()->getId() == 1) {
            if ($request->isMethod('POST')) {
                $this->get('role_service')->adminOrException();

                $status = $this->getDoctrine()->getRepository('AppBundle:ArticleStatus')
                    ->find($request->request->get('status_id'));

                if (!$status) {
                    $this->statusNotFound();
                }

                if ($status->getId() == 2) {
                    $article->setLink($request->request->get('link'));
                }

                $article->setStatus($status);
                $em = $this->getDoctrine()->getManager();
                $em->merge($article);
                $em->flush();

                $this->sendMailStatusArticle($article);

                return $this->redirectToRoute('get_article', [
                    'id' => $article->getId()
                ]);
            }
        }

        return $this->render('AppBundle:Article/Partial:patch_article_status.html.twig', [
            'article' => $article,
            'myVote' => $myVote
        ]);
    }

    private function sendMailNewArticle(Article $article)
    {
        $users = $this->getDoctrine()->getRepository('AppBundle:User')
            ->findModerators();

        foreach ($users as $user) {
            $message = (new \Swift_Message())
                ->setSubject($this->get('translator')->trans('email.new-article.title'))
                ->setFrom('no-reply@darkmira.com', 'Darkmira')
                ->setTo($user->getEmail())
                ->setBody(
                    $this->get('templating')->render('@App/Email/new_article.html.twig', [
                        'article' => $article
                    ]),
                    'text/html'
                );
            $this->get('mailer')->send($message);
        }
    }

    private function sendMailVoteArticle(ArticleVote $vote)
    {
        $users = $this->getDoctrine()->getRepository('AppBundle:User')
            ->findModerators();

        foreach ($users as $user) {
            $message = (new \Swift_Message())
                ->setSubject($this->get('translator')->trans('email.vote-article.title'))
                ->setFrom('no-reply@darkmira.com', 'Darkmira')
                ->setTo($user->getEmail())
                ->setBody(
                    $this->get('templating')->render('@App/Email/vote_article.html.twig', [
                        'article' => $vote->getArticle(),
                        'vote' => $vote
                    ]),
                    'text/html'
                );
            $this->get('mailer')->send($message);
        }
    }

    private function sendMailStatusArticle(Article $article)
    {
        $users = $this->getDoctrine()->getRepository('AppBundle:User')
            ->findModerators();
        $users[] = $this->getUser();

        foreach ($users as $user) {
            $message = (new \Swift_Message())
                ->setSubject($this->get('translator')->trans('email.status-article.title'))
                ->setFrom('no-reply@darkmira.com', 'Darkmira')
                ->setTo($user->getEmail())
                ->setBody(
                    $this->get('templating')->render('@App/Email/status_article.html.twig', [
                        'article' => $article
                    ]),
                    'text/html'
                );
            $this->get('mailer')->send($message);
        }
    }

    /**
     * @return NotFoundHttpException
     */
    private function articleNotFound(): NotFoundHttpException
    {
        throw new NotFoundHttpException('Article not found.');
    }

    /**
     * @return NotFoundHttpException
     */
    private function statusNotFound(): NotFoundHttpException
    {
        throw new NotFoundHttpException('Status not found.');
    }
}
