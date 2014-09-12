<?php

return array(
    'example' => array(
        'route' => '/example',
        'paths' => array(
            'module'    =>  'Foo',
            'controller' => 'Frontend\Example',
            'action'    =>  'index',
            'auth'  =>  false
        ),
    ),
    'list' =>  array(
        'route' =>  '/list',
        'paths' =>  array(
            'module'    =>  'Foo',
            'controller'    =>  'Frontend\Crud',
            'action'    =>  'list',
            'auth'  =>  false
        )
    ),
);