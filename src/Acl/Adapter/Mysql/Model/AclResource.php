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

use Phalcon\Mvc\Model\Relation;

class AclResource extends \Phalcon\Mvc\Model
{
    use NameFinderTrait;
    
    const DEFAULT_ALIAS = 'ar';

    /**
     * @var integer
     */
    public $id;
    
    /**
     * @var string
     */
    public $name;
    
    /**
     * @var string
     */
    public $description;
    
    /**
     * @var string
     */
    public $scope;
    
    public function __toString()
    {
        return str_replace('\\', '-', $this->name);
    }
    
    public function initialize()
    {
        $this->hasMany("id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess", "acl_resource_id", [
            'alias'  => AclResourceAccess::DEFAULT_ALIAS,
            'foreignKey' => [
                'action' => Relation::ACTION_CASCADE
            ]
        ]);
        $this->hasMany("id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList", "acl_resource_id", [
            'alias'  => AclAccessList::DEFAULT_ALIAS,
            'foreignKey' => [
                'action' => Relation::ACTION_CASCADE
            ]
        ]);
    }
    
    public function getSource()
    {
        return 'acl_resources';
    }
    
    /**
     * @return AclAccessList[]
     */
    public function getAccessLists()
    {
        return $this->getRelated(AclAccessList::DEFAULT_ALIAS);
    }
    
    /**
     * @return AclResourceAccess[]
     */
    public function getResourceAccesses()
    {
        return $this->getRelated(AclResourceAccess::DEFAULT_ALIAS);
    }
    
    /**
     * Casts related accesses used in \Vegas\Security\Acl\Resource
     * @return array
     */
    public function getAccessesAsArray()
    {
        $result = [];
        foreach ($this->getResourceAccesses() as $access) {
            $result[] = $access->toAccessArray();
        }
        return $result;
    }

}
