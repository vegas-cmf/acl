<?php
/**
 * @author Sławomir Żytko <slawek@amsterdam-standard.pl>
 * @copyright (c) 2014, Amsterdam Standard
 */

error_reporting(E_ALL);

define('APP_ROOT', dirname(dirname(__FILE__)));

try {
    require APP_ROOT . '/../../vendor/autoload.php';
    require APP_ROOT . '/app/Bootstrap.php';
    $config = require APP_ROOT . '/app/config/config.php';

    $bootstrap = new \Bootstrap(new \Phalcon\Config($config));

    echo $bootstrap->setup()->run($_SERVER['REQUEST_URI']);
} catch (\Exception $ex) {
    echo $ex->getMessage();
    echo $ex->getTraceAsString();
}