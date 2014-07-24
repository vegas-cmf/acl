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
        
        try {
            $resourceModel = $this->getResourceModel($resource->getName());            
        } catch (ResourceNotExistsException $e) {
            $resourceModel = new AclResource;            
        }
        $resourceModel->save([
                'name'        => $this->filterResourceName($resource->getName()),
                'description' => $resource->getDescription(),
                'scope'       => $resource->getScope()
            ]);

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
        $resourceModel = $this->getResourceModel($resourceName);
        
        $accesses = is_string($accessList) ?  [$accessList] : $accessList;
        
        foreach ($accesses as $access) {
            if (!is_array($access)) {
                $access = [
                    'name' => $access,
                    'description' => ucfirst($access),
                    'inherit' => null
                ];
            }
            
            try {
                $this->getResourceAccessModel($access['name'], $resourceModel->name);
            } catch (ResourceAccessNotExistsException $e) {
                (new AclResourceAccess)->create([
                        'acl_resource_id' => $resourceModel->id,
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
     * @return boolean
     */
    public function dropResourceAccess($resourceName, $accessList)
    {
        $accesses = is_string($accessList) ?  [$accessList] : $accessList;
        
        $sanitizedResourceName = $this->filterResourceName($resourceName);

        foreach ($accesses as $access) {
            $this->getResourceAccessModel($access, $sanitizedResourceName)
                    ->delete();
        }
        
        return true;
    }
    
    /**
     * @param $name
     * @param $resourceName
     * @throws Exception\ResourceAccessNotExistsException
     * @return AclResourceAccess
     */
    protected function getResourceAccessModel($name, $resourceName)
    {
        $model = AclResourceAccess::findFirstByNameAndResource($name, $this->filterResourceName($resourceName));
        if (!$model) {
            throw new ResourceAccessNotExistsException($name, $resourceName);
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
        $resourceObject = new Resource($resource->name, $resource->description);
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
            throw new RoleNotExistsException($role);
        }
        return $model;
    }
    
    /**
     * Gets role with all its accesses
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
            return $access->allowed ? Acl::ALLOW : Acl::DENY;
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
     * Example:
     * <code>
     * //Allow access to guests to search on customers
     * $acl->allow('guests', 'customers', 'search');
     * //Allow access to guests to search or create on customers
     * $acl->allow('guests', 'customers', array('search', 'create'));
     * //Allow admin access to role
     * $acl->allow('admins', 'all', '*');
     * </code>
     *
     * @param string $roleName
     * @param string $resourceName
     * @param mixed  $access
     * @throws RoleNotExistsException
     * @throws ResourceNotExistsException
     * @throws Exception
     */
    public function allow($roleName, $resourceName, $access)
    {
        $roleModel = $this->getRoleModel($roleName);
        $resourceModel = $this->getResourceModel($resourceName);
        
        $acls = $this->getValidatedAclModels($roleName, $resourceName, $access);
        
        foreach ($acls as $acl) {
            
            if ($acl instanceof AclAccessList) {
                $acl->save(['allowed' => Acl::ALLOW]);
                continue;
            }
            
            $accessModel = $this->getResourceAccessModel($acl, $resourceName);
            (new AclAccessList())->create([
                'acl_role_id'            => $roleModel->id,
                'acl_resource_id'        => $resourceModel->id,
                'acl_resource_access_id' => $accessModel->id,
                'allowed'                => Acl::ALLOW
            ]);
        }
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Deny access to guests to search on customers
     * $acl->deny('guests', 'customers', 'search');
     * //Deny access to guests to search or create on customers
     * $acl->deny('guests', 'customers', array('search', 'create'));
     * //Remove admin access to role
     * $acl->deny('admins', 'all', '*');
     * </code>
     *
     * @param  string  $roleName
     * @param  string  $resourceName
     * @param  mixed   $access
     * @throws RoleNotExistsException
     * @throws ResourceNotExistsException
     * @throws Exception
     */
    public function deny($roleName, $resourceName, $access)
    {
        $this->getRoleModel($roleName);
        $this->getResourceModel($resourceName);
        
        $acls = $this->getValidatedAclModels($roleName, $resourceName, $access);
        
        foreach ($acls as $acl) {
            ($acl instanceof AclAccessList) && $acl->delete();
        }
    }
    
    /**
     * Retrieves existing ACL models with string names for non-existing.
     * @param string $roleName
     * @param string $resourceName
     * @param mixed $access array or string
     * @return AclAccessList[] array with AclAccessList models or string names on non-existing ACLs
     * @throws Exception
     */
    protected function getValidatedAclModels($roleName, $resourceName, $access)
    {        
        if (($resourceName === Resource::WILDCARD || $access === Resource::ACCESS_WILDCARD)
            && !($resourceName === Resource::WILDCARD && $access === Resource::ACCESS_WILDCARD)) {
            throw new Exception("Cannot create access to '{$access}' in '{$resourceName}' for role {$roleName}");
        }
        $accesses = is_array($access) ? $access : [$access];
        
        $sanitizedResourceName = $this->filterResourceName($resourceName);
        return array_map(function($accessName) use ($roleName, $sanitizedResourceName) {
            $acl = AclAccessList::findFirstByRoleResourceAndAccess($roleName, $sanitizedResourceName, $accessName);
            return $acl ? $acl : $accessName;
        }, $accesses);
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