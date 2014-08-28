<?php
//Test Suite bootstrap
include __DIR__ . "/../vendor/autoload.php";

define('TESTS_ROOT_DIR', dirname(__FILE__));

$configArray = require_once dirname(__FILE__) . '/config.php';

$config = new \Phalcon\Config($configArray);
$di = new \Phalcon\DI\FactoryDefault();

$di->set('config', $config);

$di->set('mongo', function() use ($config) {
    $mongo = new \MongoClient();
    return $mongo->selectDb($config->mongo->db);
}, true);

$di->set('db', function() use ($config) {
    $arrayConfig = (array)$config->db;
    return new \Phalcon\Db\Adapter\Pdo\Mysql($arrayConfig);
}, true);


$di->set('acl', function() {
    $aclAdapter = new \Vegas\Security\Acl\Adapter\Mongo();
    $acl = new \Vegas\Security\Acl($aclAdapter);

    return $acl;
}, true);

$di->set('acl_mysql', function() {
    $aclAdapter = new \Vegas\Security\Acl\Adapter\Mysql();
    
    $acl = new \Vegas\Security\Acl($aclAdapter);
    
    return $acl;
}, true);

use \Vegas\Mvc\View;
$di->set('view', function(){
    $view = new View();
    $view->disableLevel(array(
        View::LEVEL_LAYOUT => true,
        View::LEVEL_MAIN_LAYOUT => true
    ));

    return $view;
}, true);

\Phalcon\DI::setDefault($di);