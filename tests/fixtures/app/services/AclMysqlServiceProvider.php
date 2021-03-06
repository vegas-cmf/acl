<?php
/**
 * This file is part of Vegas package
 *
 * @author Radosław Fąfara <radek@archdevil.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */ 
use Phalcon\DiInterface;
use Vegas\DI\ServiceProviderInterface;

/**
 * Class AclMysqlServiceProvider
 */
class AclMysqlServiceProvider implements ServiceProviderInterface
{

    const SERVICE_NAME = 'acl_mysql';

    /**
     * {@inheritdoc}
     */
    public function register(DiInterface $di)
    {
        $di->set(self::SERVICE_NAME, function() {
            $aclAdapter = new \Vegas\Security\Acl\Adapter\Mysql();
            $acl = new \Vegas\Security\Acl($aclAdapter);

            return $acl;
        });
    }
    
    /**
     * {@inheritdoc}
     */
    public function getDependencies()
    {
        return [
            DbServiceProvider::SERVICE_NAME
        ];
    }
}
 