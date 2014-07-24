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
use Vegas\Security\Acl\Resource;

/**
 * @use \Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess
 * @package Vegas\Security\Acl\Adapter\Mysql\Model
 *
 * Custom implementation of ACL used in MySQL databases.
 * Keeps information about specific element of resource (e.x. action in controller).
 */
class AclResourceAccess extends \Phalcon\Mvc\Model
{
    const DEFAULT_ALIAS = 'ara';

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
    public $inherit;
    
    /**
     * @return string
     */
    public function __toString()
    {
        return str_replace('\\', '-', $this->name);
    }
    
    public function initialize()
    {
        $this->belongsTo("acl_resource_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource", "id", [
            'alias' => AclResource::DEFAULT_ALIAS,
        ]);
        $this->hasMany("id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList", "acl_resource_access_id", [
            'alias'  => AclAccessList::DEFAULT_ALIAS,
            'foreignKey' => [
                'action' => Relation::ACTION_CASCADE
            ]
        ]);
    }
    
    public function getSource()
    {
        return 'acl_resources_accesses';
    }
    
    /**
     * @return AclAccessList[]
     */
    public function getAccessLists()
    {
        return $this->getRelated(AclAccessList::DEFAULT_ALIAS);
    }
    
    /**
     * @return AclResource
     */
    public function getResource()
    {
        return $this->getRelated(AclResource::DEFAULT_ALIAS);
    }
    
    /**
     * Check if access is '*' type
     * @return bool
     */
    public function isWildcard()
    {
        return $this->name === Resource::ACCESS_WILDCARD;
    }
    
    /**
     * @return array
     */
    public function toAccessArray()
    {
        return [
            'access_name'          => (string)$this,
            'access_description'   => $this->description
        ];
    }
    
    /**
     * @param string $name
     * @param string $resource
     * @return AclResourceAccess|null
     */
    public static function findFirstByNameAndResource($name, $resource)
    {
        $alias = self::DEFAULT_ALIAS;
        $relatedAlias = AclResource::DEFAULT_ALIAS;
        return (new self)->getQueryBuilder()
                ->addFrom('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess', self::DEFAULT_ALIAS)
                ->innerJoin("\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource", "[{$alias}].acl_resource_id = [{$relatedAlias}].id", AclResource::DEFAULT_ALIAS)
                ->where("[{$relatedAlias}].name = :resource:")
                ->andWhere("[{$alias}].name = :access: OR [{$alias}].inherit = :access:")
                ->getQuery()
                    ->execute([
                        'resource'  => $resource,
                        'access'    => $name
                    ])
                    ->getFirst();
    }
    
    /**
     * @return \Phalcon\Mvc\Model\Query\Builder
     */
    public function getQueryBuilder()
    {
        return $this->_modelsManager->createBuilder();
    }

}
