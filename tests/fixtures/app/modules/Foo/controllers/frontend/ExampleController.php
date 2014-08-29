<?php

namespace Foo\Controllers\Frontend;

use \Vegas\Mvc\View;

/**
 * Class ExampleController
 *
 * @ACL(name="mvc:foo:Frontend\Example", description="Example controller")
 * @package Foo\Controllers\Frontend
 */
class ExampleController extends \Vegas\Mvc\Controller\ControllerAbstract
{
    public function initialize()
    {
        parent::initialize();
        $this->view->setRenderLevel(View::LEVEL_NO_RENDER);
    }
    
    /**
     * @ACL(name="index", description="Index action")
     */
    public function indexAction()
    {
        echo 'INDEX ACTION';
    }
}