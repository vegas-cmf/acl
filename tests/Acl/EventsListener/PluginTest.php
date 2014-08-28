<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Tests\Acl\EventsListener;

use Phalcon\DI;

class FakeAuth {

    public function isAuthenticated()
    {
        return true;
    }
}

class FakeNoAuth {

    public function isAuthenticated()
    {
        return false;
    }
}

class PluginTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param string $url
     * @param \Phalcon\DI\FactoryDefault $di
     */
    private function runApplication($url, DI\FactoryDefault $di = null)
    {
        require_once dirname(__DIR__) . '/../fixtures/app/Bootstrap.php';
        $config = require dirname(__DIR__) . '/../fixtures/app/config/config.php';

        $config = new \Phalcon\Config($config);
        $bootstrap = new \Bootstrap($config);
        if ($di != null) {
            $bootstrap ->setDi($di);
        }

        $bootstrap->setup()->run($url);
    }
    
    public function testBeforeExecuteRoute()
    {
        $di = DI::getDefault();
        $this->runApplication('/example', $di);
    }
}