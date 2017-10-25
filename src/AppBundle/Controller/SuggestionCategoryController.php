<?php
namespace AppBundle\Controller;

use AppBundle\Entity\SuggestionCategory;
use AppBundle\Form\Type\SuggestionCategoryType;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;


class SuggestionCategoryController extends Controller
{
    /**
     * @Route("/suggestions/categories", name="get_suggestions_categories")
     * @Method({"GET"})
     * @return Response
     */
    public function getCategoriesAction(): Response
    {
        $this->get('role_service')->adminOrException();
        $categories = $this->getDoctrine()->getRepository('AppBundle:SuggestionCategory')
            ->findAll();

        return $this->render('AppBundle:Suggestion:get_categories.html.twig', [
            'categories' => $categories
        ]);
    }

    /**
     * @Route("/suggestions/categories/add", name="post_suggestions_categories")
     * @Method({"GET", "POST"})
     * @param Request $request
     * @return Response
     */
    public function postCategoriesAction(Request $request): Response
    {
        $this->get('role_service')->adminOrException();
        $category = new SuggestionCategory();
        $form = $this->createForm(SuggestionCategoryType::class, $category);

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $em = $this->getDoctrine()->getManager();
            $em->persist($category);
            $em->flush();

            return $this->redirectToRoute('get_suggestions_categories');
        }

        return $this->render('AppBundle:Suggestion:post_categories.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route("/suggestions/categories/{id}/remove", name="delete_suggestions_category")
     * @Method({"GET"})
     * @param int $id
     * @return Response
     */
    public function deleteCategoryAction(int $id): Response
    {
        $this->get('role_service')->adminOrException();
        $category = $this->getDoctrine()->getRepository('AppBundle:SuggestionCategory')
            ->find($id);

        if (!$category) {
            $this->CategoryNotFound();
        }

        if (count($category->getSuggestions()) > 0) {
            return $this->redirectToRoute('get_suggestions_categories');
        }

        $em = $this->getDoctrine()->getManager();
        $em->remove($category);
        $em->flush();

        return $this->redirectToRoute('get_suggestions_categories');
    }

    /**
     * @return NotFoundHttpException
     */
    private function categoryNotFound(): NotFoundHttpException
    {
        throw new NotFoundHttpException('Category not found.');
    }
}
