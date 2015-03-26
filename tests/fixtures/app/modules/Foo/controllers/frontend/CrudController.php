<?php
namespace Foo\Controllers\Frontend;

/**
 * Class CrudController
 *
 * @ACL(name="mvc:foo:Frontend\Crud", description="Example crud controller")
 * @package Foo\Controllers\Frontend
 */
class CrudController extends \Vegas\Mvc\Controller\CrudAbstract
{
    /**
     * @ACL(name="index", description="Index action")
     */
    public function indexAction()
    {
        echo 'INDEX ACTION';
    }
    /**
     * @ACL(name="show", description="Show action")
     */
    public function showAction($id)
    {
        echo 'SHOW ACTION';
    }
    /**
     * @ACL(name="list", description="List action")
     */
    public function listAction()
    {
        echo 'LIST ACTION';
    }
    /**
     * @ACL(name="test", description="Test action")
     */
    public function testAction()
    {
        echo 'TEST ACTION';
    }
    /**
     * @ACL(name="test2", inherit="test")
     */
    public function test2Action()
    {
        echo 'TEST 2 ACTION';
    }
}