<?php
namespace Foo\Controllers\Frontend;

/**
 * Class ExampleController
 *
 * @ACL(name="mvc:foo:Frontend\Example", description="Example controller")
 * @package Foo\Controllers\Frontend
 */
class ExampleController extends \Vegas\Mvc\Controller\ControllerAbstract
{
    /**
     * @ACL(name="index", description="Index action")
     */
    public function indexAction()
    {
        echo 'INDEX ACTION';
    }
}