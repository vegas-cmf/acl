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

namespace Vegas\Security\Acl\Adapter;

use Phalcon\Acl\Adapter as PhalconAdapter;
use Phalcon\Acl;
use Phalcon\DI;
use Vegas\Security\Acl\Adapter\Exception\ResourceNotExistsException;
use Vegas\Security\Acl\Adapter\Exception\RoleNotExistsException;
use Vegas\Security\Acl\Adapter\Exception\ResourceAccessNotExistsException;
use Vegas\Security\Acl\Role;
use Vegas\Security\Acl\Resource;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclAccessList;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResource;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclResourceAccess;
use Vegas\Security\Acl\Adapter\Mysql\Model\AclRole;

/**
 * @use \Phalcon\Acl\Adapter\Mysql
 * @package Vegas\Security\Acl\Adapter
 *
 * ACL adapter for MySQL based databases.
 * Integrated with models from \Vegas\Security\Acl\Adapter\Mysql\Model namespace.
 * Needs to have 'db' configured in DI so that modelsManager is available.
 */
class Mysql extends PhalconAdapter implements AdapterInterface
{
    
    /**
     * @param array $options
     * @throws Exception
     */
    public function __construct($options = array())
    {
        if (empty($options)) {
            $options = array(
                'roles'             =>  'vegas_acl_roles',
                'resources'         =>  'vegas_acl_resources',
                'resourcesAccesses' =>  'vegas_acl_resources_accesses',
                'accessList'        =>  'vegas_acl_access_list'
            );
        }
        if (!DI::getDefault()->get('modelsManager')) {
            throw new Exception("Database connection has to be configured");
        }
        
        if (!is_array($options)) {
            throw new Exception("Acl options must be an array");
        }
        
        if (!isset($options['roles'])) {
            throw new Exception("Parameter 'roles' is required");
        }

        if (!isset($options['resources'])) {
            throw new Exception("Parameter 'resources' is required");
        }

        if (!isset($options['resourcesAccesses'])) {
            throw new Exception("Parameter 'resourcesAccesses' is required");
        }

        if (!isset($options['accessList'])) {
            throw new Exception("Parameter 'accessList' is required");
        }

        $this->options = $options;
        $this->_defaultAccess = Acl::DENY;
    }
    
    /**
     * Removes modules namespace backslashes
     *
     * @param $resourceName
     * @return string
     */
    private function filterResourceName($resourceName)
    {
        return str_replace('\\', '-', $resourceName);
    }
    
    /**
     * {@inheritdoc}
     * Example:
     * <code>$acl->addRole(new Phalcon\Acl\Role('administrator'), 'consultor');</code>
     * <code>$acl->addRole('administrator', 'consultor');</code>
     *
     * @param string $role
     * @param array $accessInherits
     * @return boolean
     */
    public function addRole($role, $accessInherits = null)
    {
        if (!($role instanceof Role)) {
            $role = new Role($role, '');
        }

        try {
            $this->getRole($role->getName());
            
        } catch (RoleNotExistsException $e) {
            
            $roleModel = new AclRole;
            $roleModel->create([
                'name'          => $role->getName(),
                'description'   => $role->getDescription(),
                'removable'     => $role->isRemovable()
            ]);
            $resource = $this->getResourceModel(Resource::WILDCARD);
            (new AclAccessList)->create([
                'acl_role_id'               => $roleModel->id,
                'acl_resource_id'           => $resource->id,
                'acl_resource_access_id'    => AclResourceAccess::findFirstByNameAndResource(Resource::WILDCARD, $resource)->id,
                'allowed'                   => $this->_defaultAccess
            ]);
        }

        if ($accessInherits) {
            return $this->addInherit($role->getName(), $accessInherits);
        }

        return true;
    }
    
    /**
     * {@inheritdoc}
     *
     * @param string $roleName
     * @param string $roleToInherit
     * @throws \Phalcon\Acl\Exception
     */
    public function addInherit($roleName, $roleToInherit)
    {
        //finds role model
        $role = $this->getRoleModel($roleName);
        foreach ($role->getAccessLists() as $accessList) {
            if ($accessList->allowed) {
                $this->allow($roleName, $accessList->getResource(), $accessList->getResourceAccess());
            } else {
                $this->deny($roleName, $accessList->getResource(), $accessList->getResourceAccess());
            }
        }

        return true;
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Add a resource to the the list allowing access to an action
     * $acl->addResource(new \Phalcon\Acl\Resource('customers'), 'search');
     * $acl->addResource('customers', 'search');
     * //Add a resource  with an access list
     * $acl->addResource(new \Phalcon\Acl\Resource('customers'), array('create', 'search'));
     * $acl->addResource('customers', array('create', 'search'));
     * </code>
     *
     * @param  \Phalcon\Acl\Resource $resource
     * @param  array|string          $accessList
     * @return boolean
     */
    public function addResource($resource, $accessList = null)
    {
        if (!($resource instanceof Resource)) {
            $resource = new Resource($resource);
        }

        $currentResource = AclResource::findFirstByName($this->filterResourceName($resource->getName()));
        $data = [
                'name'        => $this->filterResourceName($resource->getName()),
                'description' => $resource->getDescription(),
                'scope'       => $resource->getScope()
            ];
        
        if (!$currentResource) {
            (new AclResource())->save($data);
            $this->addResourceAccess($resource->getName(), Resource::WILDCARD);
        } else {
            $currentResource->save($data);
        }

        if ($accessList) {
            return $this->addResourceAccess($resource->getName(), $accessList);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string                 $resourceName
     * @param  array|string           $accessList
     * @return boolean
     * @throws \Phalcon\Acl\Exception
     */
    public function addResourceAccess($resourceName, $accessList)
    {
        if (!$this->isResource($resourceName)) {
            throw new Exception("Resource '{$resourceName}' does not exist in ACL");
        }
        $sanitizedResourceName = $this->filterResourceName($resourceName);
        
        if (is_string($accessList)) {
            $accesses = [$accessList];
        } else {
            $accesses = $accessList;
        }
        
        foreach ($accesses as $access) {
            if (!is_array($access)) {
                $access = [
                    'name' => $access,
                    'description' => ucfirst($access),
                    'inherit' => null
                ];
            }
            
            try {
                $this->getResourceAccessModel($access['name'], $sanitizedResourceName);
            } catch (ResourceAccessNotExistsException $e) {
                (new AclResourceAccess)->create([
                        'acl_resource_id' => AclResource::findFirstByName($sanitizedResourceName)->id,
                        'name'    => $access['name'],
                        'description' => $access['description'],
                        'inherit' => empty($access['inherit']) ? null : $access['inherit']
                    ]);
            }
        }

        return true;
    }
    
    /**
     * @param $roleName
     */
    public function dropRole($roleName)
    {
        $this->getRoleModel($roleName)->delete();
    }

    /**
     * {@inheritdoc}
     *
     * @param string       $resourceName
     * @param array|string $accessList
     */
    public function dropResourceAccess($resourceName, $accessList)
    {
        if (is_string($accessList)) {
            $accesses = [$accessList];
        } else {
            $accesses = $accessList;
        }
        $sanitizedResourceName = $this->filterResourceName($resourceName);

        foreach ($accesses as $access) {
            $this->getResourceAccessModel($access, $sanitizedResourceName)
                    ->delete();
        }
    }
    
    /**
     * @param $name
     * @param $resourceName
     * @throws Exception\ResourceAccessNotExistsException
     * @return AclResourceAccess
     */
    protected function getResourceAccessModel($name, $resourceName)
    {
        $model = AclResourceAccess::findFirstByNameAndResource($this->filterResourceName($name), $resourceName);
        if (!$model) {
            throw new ResourceAccessNotExistsException();
        }
        return $model;
    }
    
    /**
     * @param $name
     * @throws Exception\ResourceNotExistsException
     * @return AclResource
     */
    protected function getResourceModel($name)
    {
        $model = AclResource::findFirstByName($this->filterResourceName($name));
        if (!$model) {
            throw new ResourceNotExistsException($name);
        }
        return $model;
    }
    
    /**
     * @param $name
     * @return Resource|null
     */
    public function getResource($name)
    {
        $resource = $this->getResourceModel($name);
        $resourceObject = new Resource($resource->getName(), $resource->getDescription());
        $resourceObject->setAccesses($resource->getAccessesAsArray());

        return $resourceObject;
    }

    /**
     * {@inheritdoc}
     *
     * @return \Phalcon\Acl\Resource[]
     */
    public function getResources()
    {
        $resources = array();

        foreach (AclResource::find() as $row) {
            $resources[] = $this->getResource($row);
        }

        return $resources;
    }
    
    /**
     * @param $role
     * @throws Exception\RoleNotExistsException
     * @return AclRole
     */
    protected function getRoleModel($role)
    {
        $model = AclRole::findFirstByName($role);
        if (!$model) {
            throw new RoleNotExistsException();
        }
        return $model;
    }
    
    /**
     * Gets role with all its accesses
     * Skips wildcard (*) accesses
     * 
     * @param $role
     * @return \Vegas\Security\Acl\Role
     */
    public function getRole($role)
    {
        if (!($role instanceof AclRole)) {
            $role = $this->getRoleModel($role);
        }

        $roleObject = new Role($role, $role->description);
        $roleObject->setRemovable($role->removable);
        $roleObject->setId($role->id);
        
        foreach ($role->getAccessLists() as $access) {
            if ($access->getResourceAccess()->isWildcard()) {
                continue;       //skip * accesses
            }
            $roleObject->addAccess($access->toAccessArray());
        }

        return $roleObject;
    }

    /**
     * {@inheritdoc}
     *
     * @return \Vegas\Security\Acl\Role[]
     */
    public function getRoles()
    {
        $roles = array();

        foreach (AclRole::find() as $row) {
            $roles[] = $this->getRole($row);
        }

        return $roles;
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Does Andres have access to the customers resource to create?
     * $acl->isAllowed('Andres', 'Products', 'create');
     * //Do guests have access to any resource to edit?
     * $acl->isAllowed('guests', '*', 'edit');
     * </code>
     *
     * @param  string  $role
     * @param  string  $resourceName
     * @param  string  $access
     * @return boolean
     */
    public function isAllowed($role, $resourceName, $access)
    {
        $resourceName = $this->filterResourceName($resourceName);
        $access = AclAccessList::findFirstByRoleResourceAndAccess($role, $resourceName, $access);
        if ($access instanceof AclAccessList) {
            return (bool) $access->allowed;
        }

        /**
         * Check if there is an common rule for that resource
         */
        $access = AclAccessList::findFirstByRoleResourceAndAccess($role, $resourceName, Resource::WILDCARD);
        if ($access instanceof AclAccessList) {
            return (bool) $access->allowed;
        }

        return $this->_defaultAccess;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string  $resourceName
     * @return boolean
     */
    public function isResource($resourceName)
    {
        return AclResource::countByName($this->filterResourceName($resourceName)) > 0;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string  $roleName
     * @return boolean
     */
    public function isRole($roleName)
    {
        return AclRole::countByName($this->filterResourceName($roleName)) > 0;
    }
    
    /**
     * {@inheritdoc}
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Allow access to guests to search on customers
     * $acl->allow('guests', 'customers', 'search');
     * //Allow access to guests to search or create on customers
     * $acl->allow('guests', 'customers', array('search', 'create'));
     * //Allow access to any role to browse on products
     * $acl->allow('*', 'products', 'browse');
     * //Allow access to any role to browse on any resource
     * $acl->allow('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $resourceName
     * @param mixed  $access
     */
    public function allow($roleName, $resourceName, $access = Resource::WILDCARD)
    {
        $this->allowOrDeny($roleName, $resourceName, $access, Acl::ALLOW);
    }

    /**
     * {@inheritdoc}
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Deny access to guests to search on customers
     * $acl->deny('guests', 'customers', 'search');
     * //Deny access to guests to search or create on customers
     * $acl->deny('guests', 'customers', array('search', 'create'));
     * //Deny access to any role to browse on products
     * $acl->deny('*', 'products', 'browse');
     * //Deny access to any role to browse on any resource
     * $acl->deny('*', '*', 'browse');
     * </code>
     *
     * @param  string  $roleName
     * @param  string  $resourceName
     * @param  mixed   $access
     */
    public function deny($roleName, $resourceName, $access = Resource::WILDCARD)
    {
        $this->allowOrDeny($roleName, $resourceName, $access, Acl::DENY);
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string $roleName
     * @param  string $resourceName
     * @param  string $access
     * @param  integer $action
     * @throws Exception
     */
    protected function allowOrDeny($roleName, $resourceName, $access, $action)
    {
        if (!$this->isRole($roleName)) {
            throw new Exception("Role '{$roleName}' does not exist in the list");
        }
        
        $roleModel = $this->getRoleModel($roleName);
        $resourceModel = $this->getResourceModel($resourceName);
        
        $accesses = is_array($access) ? $access : [$access];
        if (is_string($access) && $access == Resource::WILDCARD) {
            $accesses = $resourceModel->getResourceAccessesWithoutWildcard();
        } else {
            $accesses = array_map(function($name) use ($resourceModel) {
                return AclResourceAccess::findFirstByNameAndResource($name, (string)$resourceModel);
            }, $accesses);
        }
        empty($accesses) && array_push($accesses, AclResourceAccess::findFirstByNameAndResource(Resource::WILDCARD, (string)$resourceModel));
        
        foreach ($accesses as $accessModel) {
            $this->insertOrUpdateAccess($roleModel, $resourceModel, $accessModel, $action);
        }
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  AclRole $role
     * @param  AclResource $resource
     * @param  AclResourceAccess $accessDetails
     * @param  Acl $action
     * @throws Exception
     */
    protected function insertOrUpdateAccess(AclRole $role, AclResource $resource, AclResourceAccess $accessDetails, $action)
    {
        /**
         * Check if the access is valid in the resource
         */
        $exists = AclResourceAccess::findFirstByNameAndResource((string)$accessDetails, (string)$resource);
        if (!$exists) {
            throw new Exception(
                "Access '{$accessDetails}' does not exist in resource '{$resource}' in ACL"
            );
        }
        
        $access = AclAccessList::findFirstByRoleResourceAndAccess((string)$role, (string)$resource, (string)$accessDetails);
        
        if (!$access) {
            $access = new AclAccessList();
            $data = [
                'acl_role_id'            => $role->id,
                'acl_resource_id'        => $resource->id,
                'acl_resource_access_id' => $accessDetails->id,
                'allowed'                => $action
            ];
        } else {
            $data = ['allowed' => $action];
        }
        $access->save($data);

        /**
         * Update the access '*' in access_list
         */
        $exists = AclAccessList::findFirstByRoleResourceAndAccess((string)$role, (string)$resource, Resource::WILDCARD);
        $exists || (new AclAccessList)->create([
                'acl_role_id'            => $role->id,
                'acl_resource_id'        => $resource->id,
                'acl_resource_access_id' => AclResourceAccess::findFirstByNameAndResource(Resource::WILDCARD, (string)$resource)->id,
                'allowed'                => $this->_defaultAccess
            ]);

    }

    /**
     * @return mixed
     */
    public function removeResources()
    {
        foreach (AclResource::find() as $resource) {
            $resource->delete();
        }
    }

    /**
     * @return mixed
     */
    public function removeResourceAccesses()
    {
        foreach (AclResourceAccess::find() as $resourceAccess) {
            $resourceAccess->delete();
        }
    }
}