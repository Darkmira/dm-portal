<?php

namespace AppBundle\Controller;

use AppBundle\Entity\FacebookStatus;
use AppBundle\Entity\Suggestion;
use AppBundle\Entity\SuggestionStatus;
use AppBundle\Entity\TwitterStatus;
use AppBundle\Form\Type\AdditionalDescriptionType;
use AppBundle\Form\Type\SuggestionType;
use AppBundle\Services\FacebookFunctions;
use AppBundle\Services\QueryService;
use AppBundle\Services\RoleService;
use AppBundle\Services\TwitterFunctions;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use \Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class SuggestionController extends Controller
{
    /**
     * @var QueryService
     */
    private $queryServices;

    /**
     * @var TwitterFunctions
     */
    private $twitterFunctions;

    /**
     * @var RoleService
     */
    private $roleService;

    /**
     * @var FacebookFunctions
     */
    private $facebookFunctions;

    const DEFAULT_STATUS = 1;
    const PUBLISHED_STATUS = 2;

    /**
     * SuggestionController constructor.
     * @param QueryService $queryServices
     * @param TwitterFunctions $twitterFunctions
     * @param RoleService $roleService
     * @param FacebookFunctions $facebookFunctions
     */
    public function __construct(QueryService $queryServices, TwitterFunctions $twitterFunctions, RoleService $roleService, FacebookFunctions $facebookFunctions)
    {
        $this->queryServices = $queryServices;
        $this->twitterFunctions = $twitterFunctions;
        $this->roleService = $roleService;
        $this->facebookFunctions = $facebookFunctions;
    }

    /**
     * @Route("/suggestions", name="get_suggestions")
     * @Method({"GET"})
     * @return Response
     */
    public function getSuggestionsAction(): Response
    {
        $suggestions = $this->getDoctrine()->getManager()->getRepository(Suggestion::class)->findAll();

        return $this->render('AppBundle:Suggestion:get_suggestions.html.twig', ['suggestions' => $suggestions]);
    }

    /**
     * @Route("/suggestions/add", name="post_suggestions")
     * @Method({"GET", "POST"})
     * @param Request $request
     * @return Response
     */
    public function postSuggestionsAction(Request $request): Response
    {
        $suggestion = new Suggestion();

        $form = $this->createForm(SuggestionType::class, $suggestion);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            /** @var Suggestion $suggestion */
            $status = $this->queryServices->findOneOrException(SuggestionStatus::class, ['id' => 1]);

            /** @var Suggestion $suggestoin */
            $twitter_status = $this->queryServices->findOneOrException(TwitterStatus::class, ['id' => 1]);

            /** @var FacebookStatus $facebookStatus */
            $facebookStatus = $this->queryServices->findOneOrException(FacebookStatus::class, ['id' => self::DEFAULT_STATUS]);

            $file = $suggestion->getFile();
            if ($file) {
                $fileName = md5(uniqid(rand(), true));
                $extension = $file->guessExtension();
                $mimeType = $file->getMimeType();
                $file->move(
                    $this->getParameter('suggestion_directory'),
                    $fileName . '.' . $extension
                );
                $suggestion->setFileMimeType($mimeType);
                $suggestion->setFile($fileName);
                $suggestion->setFileExtension($extension);
            }
            $suggestion->setUser($this->getUser());
            $suggestion->setStatus($status);
            $suggestion->setTwitterStatus($twitter_status);
            $suggestion->setFacebookStatus($facebookStatus);

            $em = $this->getDoctrine()->getManager();
            $em->persist($suggestion);
            $em->flush();

            return $this->redirect($this->generateUrl('get_suggestions'));
        }

        return $this->render('AppBundle:Suggestion:post_suggestions.html.twig', ["form" => $form->createView()]);
    }

    /**
     * @Route("/suggestions/{id}", name="get_suggestion")
     * @Method({"GET"})
     * @return Response
     */
    public function getSuggestionAction($id): Response
    {
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);

        return $this->render('AppBundle:Suggestion:get_suggestion.html.twig', ['suggestion' => $suggestion]);
    }

    /**
     * @Route("/suggestions/download/{file}",name="get_suggestions_download")
     * @Method({"GET"})
     * @return Response
     */
    public function getSuggestionsDownloadAction($file)
    {
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['file' => $file]);

        $filename = $suggestion->getFile() . '.' . $suggestion->getFileExtension();

        $response = new Response();
        $response->headers->set('Content-type', $suggestion->getFileMimeType());
        $response->headers->set('Content-Disposition', sprintf('attachment; filename="%s"', $filename));
        $response->setContent(file_get_contents($this->getParameter('suggestion_directory') . '/' . $filename));
        $response->setStatusCode(200);
        $response->headers->set('Content-Transfer-Encoding', 'binary');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Expires', '0');

        return $response;
    }

    /**
     * @Route("/suggestions/{id}/status/{statusId}", name="get_suggestions_mark_as", requirements={
     *      "statusId": "2|3"
     * })
     * @Method({"GET"})
     */
    public function getSuggestionsMarkAsAction($id, $statusId)
    {
        $this->roleService->adminOrException();
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);
        $suggestionstatus = $this->queryServices->findOneOrException(SuggestionStatus::class, ['id' => $statusId]);

        $suggestion->setStatus($suggestionstatus);
        $this->queryServices->save($suggestion);

        return $this->redirectToRoute('get_suggestion', ['id' => $id]);
    }

    /**
     * @param $id
     * @param Request $request
     * @param Suggestion $suggestion
     * @Route("/suggestions/edit/{id}", name="admin_suggestion_edit")
     *
     * @return Response
     * @throws \Exception
     */
    public function editSuggestionAction($id, Request $request, Suggestion $suggestion): Response
    {
        $this->roleService->adminOrException();
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);

        $form = $this->createForm(AdditionalDescriptionType::class, $suggestion);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $suggestion->setAdditionalDescription($suggestion->getAdditionalDescription());
            $suggestion->setUser($this->getUser());
            $em = $this->getDoctrine()->getManager();
            $em->persist($suggestion);
            $em->flush();

            return $this->redirectToRoute('get_suggestion', ['id' => $suggestion->getId()]);
        }
        return $this->render('AppBundle:Suggestion:edit_suggestion.html.twig', [
            "form" => $form->createView(),
        ]);
    }

    /**
     * @param $id
     * @param $statusId
     * @return RedirectResponse
     */
    public function postTwitterStatusAction($id, $statusId): RedirectResponse
    {
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);
        /** @var Suggestion $suggestion */
        $twitterstatus = $this->queryServices->findOneOrException(TwitterStatus::class, ['id' => $statusId]);

        $suggestion->setTwitterStatus($twitterstatus);
        $this->queryServices->save($suggestion);

        return $this->redirectToRoute('get_suggestion', ['id' => $id]);
    }

    /**
     * @param $id
     * @param $statusId
     * @Route("/suggestions/tweet_with_media/{id}/status/{statusId}", name="tweet_withMedia"),  requirements={
     *      "statusId": "2"
     * @Method({"GET"})
     *
     * @return RedirectResponse
     */
    public function postTweetWithMediaAction($id, $statusId): RedirectResponse
    {
        $this->roleService->adminOrException();
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);

        $file = $suggestion->getFile() . '.' . $suggestion->getFileExtension();

        //to make sure that the additional description exists
        if ($suggestion->getAdditionalDescription() != null) {

            $tweet = $suggestion->getAdditionalDescription();

        } else {

            $tweet = $suggestion->getDescription();
        }

        // To select the right method (with media OR without media)
        if ($suggestion->getFile() != null) {

            $media = $this->getParameter('suggestion_directory') . '/' . $file;
            $this->twitterFunctions->postTweetWithMedia($tweet, $media);

        } else {

            $this->twitterFunctions->postTweetWithoutMedia($tweet);
        }

        return $this->postTwitterStatusAction($id, $statusId);
    }

    /**
     * @Route("/suggestions/facebook/login", name="facebook_login")
     * @return RedirectResponse
     */
    public function getFacebookLoginAction(): RedirectResponse
    {
        return $this->redirect($this->facebookFunctions->getFacebookLogin());
    }

    /**
     * @Route("/suggestions/facebook/callback", name="facebook_callback")
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function callbackAction(Request $request): RedirectResponse
    {
        $this->facebookFunctions->FacebookCallback();

        return $this->redirectToRoute('get_suggestion');

    }

    /**
     * @param $id
     * @return RedirectResponse
     */
    public function postFacebookStatusAction($id): RedirectResponse
    {
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);
        /** @var FacebookStatus $facebookStatus */
        $facebookStatus = $this->queryServices->findOneOrException(FacebookStatus::class, ['id' => self::PUBLISHED_STATUS]);

        $suggestion->setFacebookStatus($facebookStatus);
        $this->queryServices->save($suggestion);

        return $this->redirectToRoute('get_suggestion', ['id' => $id]);
    }

    /**
     * @param $id
     * @Route("/suggestions/facebook/{id}", name="facebook_message")
     * @Method({"GET"})
     *
     * @return RedirectResponse
     */
    public function postMessageOnFacebookAction($id)
    {
        $this->roleService->adminOrException();
        /** @var Suggestion $suggestion */
        $suggestion = $this->queryServices->findOneOrException(Suggestion::class, ['id' => $id]);

        $file = $suggestion->getFile() . '.' . $suggestion->getFileExtension();

        //to make sure that the additional description exists
        if ($suggestion->getAdditionalDescription() != null) {

            $message = $suggestion->getAdditionalDescription();

        } else {

            $message = $suggestion->getDescription();
        }

        // To select the right method (with media OR without media)
        if ($suggestion->getFile() != null) {

            $media = $this->getParameter('suggestion_directory') . '/' . $file;
            $this->facebookFunctions->postMessageOnFacebookWithMedia($message, $media);

        } else {

            $this->facebookFunctions->postMessageOnFacebookWithLink($message);
        }

        return $this->postFacebookStatusAction($id, self::PUBLISHED_STATUS);
    }
}
