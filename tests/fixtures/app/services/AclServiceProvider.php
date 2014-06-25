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
class AclServiceProvider implements \Vegas\DI\ServiceProviderInterface
{

    const SERVICE_NAME = 'acl';


    /**
     * Returns array of dependencies
     * <code>
     * return array(
     *      MongoServiceProvider::SERVICE_NAME,
     *      CollectionManagerServiceProvider::SERVICE_NAME
     * );
     * </code>
     *
     * @return array
     */
    public function getDependencies()
    {
        return array(
            MongoServiceProvider::SERVICE_NAME
        );
    }

    /**
     * Registers service into Dependency Injector
     *
     * @param \Phalcon\DiInterface $di
     * @return mixed
     */
    public function register(\Phalcon\DiInterface $di)
    {
        $di->set(self::SERVICE_NAME, function() {
            $aclAdapter = new \Vegas\Security\Acl\Adapter\Mongo();
            $acl = new \Vegas\Security\Acl($aclAdapter);

            return $acl;
        });
    }
}
 