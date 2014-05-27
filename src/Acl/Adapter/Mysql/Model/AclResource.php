<?php
/**
 * This file is part of Vegas package
 *
 * @author Radosław Fąfara <radek@archdevil.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
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
     * Reserved name of 'catch-all' access to all resources
     * Prepared for powerusers
     */
    const WILDCARD = 'all';

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
        $this->hasMany("acl_resource_access_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess", "id", [
            'alias'  => AclResourceAccess::DEFAULT_ALIAS,
            'foreignKey' => [
                'action' => Relation::ACTION_CASCADE
            ]
        ]);
        $this->hasMany("acl_resource_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList", "id", [
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
     * @return AclResourceAccess[]
     */
    public function getResourceAccessesWithoutWildcard()
    {
        $accesses = [];
        foreach ($this->getResourceAccesses() as $item) {
            if ($item->isWildcard()) {
                continue;   // skip '*'
            }
            $accesses[] = $item;
        }
        return $accesses;
    }
    
    /**
     * Casts related accesses used in \Vegas\Security\Acl\Resource
     * @return array
     */
    public function getAccessesAsArray()
    {
        $result = [];
        foreach ($this->getResourceAccesses() as $access) {
            if ($access->isWildcard()) {
                continue;   // skip '*' access
            }
            $result[(string)$access] = $access->description;
        }
        return $result;
    }

}
