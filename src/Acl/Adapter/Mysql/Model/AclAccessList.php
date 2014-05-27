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

/**
 * @use \Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList
 * @package Vegas\Security\Acl\Adapter\Mysql\Model
 *
 * Custom implementation of ACL used in MySQL databases.
 * Keeps information about access (whether it is allowed or not) for related tables.
 */
class AclAccessList extends \Phalcon\Mvc\Model
{
    const DEFAULT_ALIAS = 'aal';

    /**
     * @var integer
     */
    public $id;

    /**
     * @var integer (0|1)
     */
    public $allowed;
    
    public function initialize()
    {
        $this->belongsTo("acl_role_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclRole", "id", [
            'alias'  => AclRole::DEFAULT_ALIAS,
        ]);
        $this->belongsTo("acl_resource_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource", "id", [
            'alias'  => AclResource::DEFAULT_ALIAS,
        ]);
        $this->belongsTo("acl_resource_access_id", "\Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess", "id", [
            'alias'  => AclResourceAccess::DEFAULT_ALIAS,
        ]);
    }
    
    /**
     * @return string
     */
    public function getSource()
    {
        return 'acl_access_list';
    }
    
    /**
     * @return AclResource
     */
    public function getResource()
    {
        return $this->getRelated(AclResource::DEFAULT_ALIAS);
    }
    
    /**
     * @return AclResourceAccess
     */
    public function getResourceAccess()
    {
        return $this->getRelated(AclResourceAccess::DEFAULT_ALIAS);
    }
    
    /**
     * @return AclRole
     */
    public function getRole()
    {
        return $this->getRelated(AclRole::DEFAULT_ALIAS);
    }
    
    /**
     * Casts model into array used as access in \Vegas\Security\Acl\Role
     * @return array
     */
    public function toAccessArray()
    {
        return [
            'access_name'       => (string)$this->getResourceAccess(),
            'resources_name'    => (string)$this->getResource(),
            'allowed'           => $this->allowed
        ];
    }
    
    /**
     * Retrieves DB record for specified ACL settings.
     * 
     * @param string $role
     * @param string $resource
     * @param string $access
     * @return AclAccessList|null
     */
    public static function findFirstByRoleResourceAndAccess($role, $resource, $access)
    {
        $alias = self::DEFAULT_ALIAS;
        $roleAlias = AclRole::DEFAULT_ALIAS;
        $resourceAlias = AclResource::DEFAULT_ALIAS;
        $accessAlias = AclResourceAccess::DEFAULT_ALIAS;
        
        return (new self)->getQueryBuilder()
                ->addFrom('\Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList', $alias)
                ->innerJoin('\Vegas\Security\Acl\Adapter\Mysql\Model\AclRole', "[{$alias}].acl_role_id = [{$roleAlias}].id", $roleAlias)
                ->innerJoin('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResource', "[{$alias}].acl_resource_id = [{$resourceAlias}].id", $resourceAlias)
                ->innerJoin('\Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess', "[{$alias}].acl_resource_access_id = [{$accessAlias}].id", $accessAlias)
                ->where("
                    [{$roleAlias}].name = :role: AND [{$resourceAlias}].name = :resource:
                    AND (
                        [{$accessAlias}].name = :access: OR [{$accessAlias}].inherit = :access:
                    )
                    ")
                ->orWhere("[{$roleAlias}].name = :role: AND [{$resourceAlias}].name = :all:")
                //->orderBy("[{$accessAlias}].name DESC, [{$resourceAlias}].name DESC")
                ->getQuery()
                    ->execute([
                            'role'      => $role,
                            'resource'  => $resource,
                            'access'    => $access,
                            'all'       => AclResource::WILDCARD
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
