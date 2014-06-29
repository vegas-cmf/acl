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

namespace Vegas\Security\Acl\Adapter\Mysql\Model;

/**
 * Helper to find/count all records based on their name.
 * @fixme could be generalized and moved under \Vegas\Mvc\Model\* namespace
 */
trait NameFinderTrait
{
    /**
     * @param string $name
     * @return \Phalcon\Mvc\Model|null
     */
    public static function findFirstByName($name)
    {
        $classname = get_called_class();
        return $classname::findFirst([
            'conditions'    => 'name = :name:',
            'bind'          => ['name' => $name]
        ]);
    }
    
    /**
     * @param string $name
     * @return integer
     */
    public static function countByName($name)
    {
        $classname = get_called_class();
        return $classname::count([
            'conditions'    => 'name = :name:',
            'bind'          => ['name' => $name]
        ]);
    }
}
